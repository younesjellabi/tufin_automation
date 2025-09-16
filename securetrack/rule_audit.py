"""Helper utilities for SecureTrack rule auditing workflows."""
from __future__ import annotations

import csv
from dataclasses import asdict, dataclass, field
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)
import re
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Literal,
    Optional,
    Sequence,
    Set,
    TextIO,
    Tuple,
    Union,
)

from .client import SecureTrackClient

__all__ = [
    "Rule",
    "Finding",
    "fetch_rules",
    "audit_rules",
    "to_json",
    "to_csv",
    "run_rule_audit",
]

IPAddress = Union[IPv4Address, IPv6Address]
IPNetwork = Union[IPv4Network, IPv6Network]

_any_tokens = {
    "any",
    "any service",
    "any-service",
    "anyservice",
    "any network",
    "any object",
    "any network object",
    "any service object",
}


@dataclass
class NetworkSpec:
    """Structured representation of network objects on a rule."""

    any: bool = False
    addresses: List[IPAddress] = field(default_factory=list)
    networks: List[IPNetwork] = field(default_factory=list)
    ranges: List[Tuple[IPAddress, IPAddress]] = field(default_factory=list)
    tokens: Set[str] = field(default_factory=set)


@dataclass
class ServiceSpec:
    """Structured representation of service objects on a rule."""

    any: bool = False
    protocols: Set[str] = field(default_factory=set)
    ports: Set[int] = field(default_factory=set)
    port_ranges: List[Tuple[int, int]] = field(default_factory=list)
    tokens: Set[str] = field(default_factory=set)


@dataclass
class Rule:
    """Canonical representation of a SecureTrack rule."""

    rule_id: Union[str, int, None]
    name: Optional[str]
    device: Optional[str]
    action: str
    source: str
    destination: str
    service: str
    hit_count: Optional[int]
    last_hit: Optional[str]
    position: Optional[int]
    raw: Dict[str, Any]
    source_spec: NetworkSpec = field(default_factory=NetworkSpec)
    destination_spec: NetworkSpec = field(default_factory=NetworkSpec)
    service_spec: ServiceSpec = field(default_factory=ServiceSpec)


@dataclass
class Finding:
    """Represents a single audit finding for a rule."""

    issue: Literal["unused", "overly_permissive", "shadowed"]
    rule_id: Union[str, int]
    device: Optional[str]
    detail: str


def fetch_rules(
    client: SecureTrackClient, device_id: Optional[str] = None
) -> List[Rule]:
    """Fetch rules from SecureTrack and convert them into :class:`Rule` objects."""

    payload = client.get_rules(device_id=device_id)
    rule_dicts = _extract_rule_dicts(payload)

    rules: List[Rule] = []
    for index, data in enumerate(rule_dicts):
        rules.append(_build_rule(data, fallback_position=index))
    return rules


def audit_rules(rules: Sequence[Rule]) -> List[Finding]:
    """Run audit checks against *rules* and return findings."""

    findings: List[Finding] = []

    for rule in rules:
        if _is_unused(rule):
            findings.append(
                Finding(
                    issue="unused",
                    rule_id=_rule_identifier(rule),
                    device=rule.device,
                    detail=_format_unused_detail(rule),
                )
            )

        if _is_overly_permissive(rule):
            findings.append(
                Finding(
                    issue="overly_permissive",
                    rule_id=_rule_identifier(rule),
                    device=rule.device,
                    detail=_format_risky_detail(rule),
                )
            )

    ordered_rules = _sort_rules_for_shadowing(rules)
    for idx, rule in enumerate(ordered_rules):
        shadowing_rule = _find_shadowing_rule(rule, ordered_rules[:idx])
        if shadowing_rule is not None:
            findings.append(
                Finding(
                    issue="shadowed",
                    rule_id=_rule_identifier(rule),
                    device=rule.device,
                    detail=_format_shadow_detail(rule, shadowing_rule),
                )
            )

    return findings


def to_json(findings: Iterable[Finding]) -> List[Dict[str, Any]]:
    """Convert findings into JSON-serialisable dictionaries."""

    return [asdict(finding) for finding in findings]


def to_csv(findings: Iterable[Finding], fp: TextIO) -> None:
    """Write findings to *fp* as CSV with a stable header."""

    writer = csv.DictWriter(fp, fieldnames=["issue", "rule_id", "device", "detail"])
    writer.writeheader()
    for finding in findings:
        writer.writerow(asdict(finding))


def run_rule_audit(
    client: SecureTrackClient,
    *,
    device_id: Optional[str] = None,
) -> List[Finding]:
    """High-level helper used by the CLI to fetch and audit rules."""

    rules = fetch_rules(client, device_id=device_id)
    return audit_rules(rules)


def _extract_rule_dicts(payload: Any) -> List[Dict[str, Any]]:
    """Normalise the payload returned by the API into a list of dictionaries."""

    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    if isinstance(payload, dict):
        for key in ("rules", "items", "data", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        if any(key in payload for key in ("id", "ruleId", "rule_id")):
            return [payload]

    return []


def _build_rule(data: Dict[str, Any], *, fallback_position: int) -> Rule:
    """Construct a :class:`Rule` from raw API data."""

    position = _int_or_none(
        _first_value(
            data,
            "position",
            "rule_position",
            "order",
            "sequence",
            "ruleOrder",
        )
    )
    if position is None:
        position = fallback_position

    rule_id = _first_value(data, "id", "ruleId", "rule_id", "uid", "ruleUid")
    name = _string_or_none(
        _first_value(data, "name", "ruleName", "displayName", "label")
    )
    device = _string_or_none(
        _first_value(data, "device_name", "deviceName", "device", "gateway")
    )
    action = _string_value(_first_value(data, "action", "ruleAction") or "")
    source = _string_value(
        _first_value(data, "source", "sources", "source_text", "src") or ""
    )
    destination = _string_value(
        _first_value(
            data,
            "destination",
            "dest",
            "destinations",
            "destination_text",
            "dst",
        )
        or ""
    )
    service = _string_value(
        _first_value(data, "service", "services", "application", "svc") or ""
    )
    hit_count = _int_or_none(
        _first_value(data, "hit_count", "hitCount", "hits", "usageCount")
    )
    last_hit = _string_or_none(
        _first_value(data, "last_hit", "lastHit", "last_hit_time", "lastUsed")
    )

    source_spec = _parse_network_spec(
        data,
        source,
        (
            "source_objects",
            "sourceObjects",
            "sources",
            "source_details",
            "sourceDetails",
            "source_list",
            "sourceList",
            "src",
            "src_objects",
            "srcObjects",
        ),
    )
    destination_spec = _parse_network_spec(
        data,
        destination,
        (
            "destination_objects",
            "destinationObjects",
            "destinations",
            "destination_details",
            "destinationDetails",
            "dest_list",
            "destList",
            "dst",
            "dst_objects",
            "dstObjects",
        ),
    )
    service_spec = _parse_service_spec(
        data,
        service,
        (
            "service_objects",
            "serviceObjects",
            "services",
            "service_details",
            "serviceDetails",
            "applications",
            "application_objects",
            "applicationObjects",
            "svc",
        ),
    )

    return Rule(
        rule_id=rule_id,
        name=name,
        device=device,
        action=action,
        source=source,
        destination=destination,
        service=service,
        hit_count=hit_count,
        last_hit=last_hit,
        position=position,
        raw=data,
        source_spec=source_spec,
        destination_spec=destination_spec,
        service_spec=service_spec,
    )


def _parse_network_spec(
    data: Dict[str, Any], fallback: str, keys: Sequence[str]
) -> NetworkSpec:
    """Extract structured network coverage information from *data*."""

    spec = NetworkSpec()
    if fallback:
        _ingest_network_value(fallback, spec)
    for key in keys:
        if key in data:
            _ingest_network_value(data[key], spec)
    return spec


def _parse_service_spec(
    data: Dict[str, Any], fallback: str, keys: Sequence[str]
) -> ServiceSpec:
    """Extract structured service coverage information from *data*."""

    spec = ServiceSpec()
    if fallback:
        _ingest_service_value(fallback, spec)
    for key in keys:
        if key in data:
            _ingest_service_value(data[key], spec)
    return spec


def _ingest_network_value(value: Any, spec: NetworkSpec) -> None:
    """Populate *spec* with data derived from *value*."""

    if value is None:
        return
    if isinstance(value, list):
        for item in value:
            _ingest_network_value(item, spec)
        return
    if isinstance(value, dict):
        _ingest_network_object(value, spec)
        return
    if isinstance(value, str):
        for token in _split_tokens(value):
            _add_network_token(token, spec)
            _register_network_literal(token, spec)
        return
    _ingest_network_value(str(value), spec)


def _ingest_network_object(obj: Dict[str, Any], spec: NetworkSpec) -> None:
    """Merge a dictionary describing a network object into *spec*."""

    if obj.get("isAny") is True:
        spec.any = True

    type_hint = _first_value(obj, "type", "objectType", "kind", "category")
    if isinstance(type_hint, str):
        normalized_type = _normalize_token(type_hint)
        if normalized_type:
            spec.tokens.add(normalized_type)
        if normalized_type in _any_tokens:
            spec.any = True

    for key in ("name", "display_name", "displayName", "label", "id", "uid"):
        value = obj.get(key)
        if isinstance(value, str):
            _add_network_token(value, spec)

    value = _first_value(obj, "value", "cidr", "address", "ip", "subnet")
    if value is not None:
        _ingest_network_value(value, spec)

    start_val = _first_value(
        obj,
        "start",
        "start_ip",
        "startIp",
        "from",
        "from_ip",
        "fromIp",
        "startAddress",
    )
    end_val = _first_value(
        obj,
        "end",
        "end_ip",
        "endIp",
        "to",
        "to_ip",
        "toIp",
        "endAddress",
    )
    if start_val is not None and end_val is not None:
        _register_network_range(str(start_val), str(end_val), spec)

    members = _first_value(obj, "members", "objects", "children", "subnets", "ips")
    if members is not None:
        _ingest_network_value(members, spec)


def _register_network_literal(value: str, spec: NetworkSpec) -> None:
    """Interpret *value* as a network construct and add it to *spec*."""

    token = value.strip()
    if not token:
        return
    try:
        address = ip_address(token)
    except ValueError:
        address = None
    if address is not None:
        spec.addresses.append(address)
        return

    try:
        network = ip_network(token, strict=False)
    except ValueError:
        network = None
    if network is not None:
        spec.networks.append(network)
        return

    if "-" in token:
        start_text, end_text = token.split("-", 1)
        _register_network_range(start_text.strip(), end_text.strip(), spec)


def _register_network_range(start: str, end: str, spec: NetworkSpec) -> None:
    """Add an IP range defined by *start* and *end* to *spec*."""

    try:
        start_addr = ip_address(start)
        end_addr = ip_address(end)
    except ValueError:
        return

    if start_addr.version != end_addr.version:
        return

    if int(start_addr) > int(end_addr):
        start_addr, end_addr = end_addr, start_addr

    spec.ranges.append((start_addr, end_addr))


def _ingest_service_value(value: Any, spec: ServiceSpec) -> None:
    """Populate *spec* with details derived from *value*."""

    if value is None:
        return
    if isinstance(value, list):
        for item in value:
            _ingest_service_value(item, spec)
        return
    if isinstance(value, dict):
        _ingest_service_object(value, spec)
        return
    if isinstance(value, str):
        for token in _split_tokens(value):
            _add_service_token(token, spec)
            _register_service_literal(token, spec)
        return
    _ingest_service_value(str(value), spec)


def _ingest_service_object(obj: Dict[str, Any], spec: ServiceSpec) -> None:
    """Merge a service object dictionary into *spec*."""

    if obj.get("isAny") is True:
        spec.any = True

    type_hint = _first_value(obj, "type", "objectType", "kind", "category")
    if isinstance(type_hint, str):
        normalized_type = _normalize_token(type_hint)
        if normalized_type:
            spec.tokens.add(normalized_type)
        if normalized_type in _any_tokens:
            spec.any = True

    for key in ("name", "display_name", "displayName", "label", "id", "uid"):
        value = obj.get(key)
        if isinstance(value, str):
            _add_service_token(value, spec)

    protocol = _first_value(
        obj,
        "protocol",
        "serviceProtocol",
        "layer4_protocol",
        "proto",
    )
    if protocol is not None:
        normalized_protocol = _normalize_protocol(protocol)
        if normalized_protocol:
            spec.protocols.add(normalized_protocol)
            spec.tokens.add(normalized_protocol)

    port = _first_value(
        obj,
        "port",
        "destination_port",
        "dest_port",
        "servicePort",
    )
    if port is not None:
        _record_port_segment(str(port), spec)

    start_port = _first_value(
        obj,
        "from",
        "from_port",
        "start",
        "start_port",
        "port_from",
    )
    end_port = _first_value(
        obj,
        "to",
        "to_port",
        "end",
        "end_port",
        "port_to",
    )
    if start_port is not None or end_port is not None:
        start = _to_int(start_port if start_port is not None else end_port)
        end = _to_int(end_port if end_port is not None else start_port)
        if start is not None and end is not None:
            if start > end:
                start, end = end, start
            spec.port_ranges.append((start, end))
            spec.tokens.add(_normalize_token(f"{start}-{end}"))
        elif start is not None:
            spec.ports.add(start)
            spec.tokens.add(_normalize_token(str(start)))
        elif end is not None:
            spec.ports.add(end)
            spec.tokens.add(_normalize_token(str(end)))

    ports_list = _first_value(
        obj,
        "ports",
        "port_list",
        "dest_ports",
        "destination_ports",
        "servicePorts",
    )
    if isinstance(ports_list, list):
        for entry in ports_list:
            _record_port_segment(str(entry), spec)

    value = obj.get("value")
    if value is not None:
        _ingest_service_value(value, spec)

    members = _first_value(obj, "members", "objects", "services", "children")
    if isinstance(members, list):
        for member in members:
            _ingest_service_value(member, spec)


def _register_service_literal(value: str, spec: ServiceSpec) -> None:
    """Interpret *value* as a service definition and populate *spec*."""

    token = value.strip()
    if not token:
        return

    lowered = token.lower()
    if lowered in {"any", "any service", "any-service"}:
        spec.any = True
        return

    if "/" in token:
        proto_part, port_part = token.split("/", 1)
        normalized_protocol = _normalize_protocol(proto_part)
        if normalized_protocol:
            spec.protocols.add(normalized_protocol)
            spec.tokens.add(normalized_protocol)
        for segment in re.split(r"[,&]", port_part):
            segment = segment.strip()
            if segment:
                _record_port_segment(segment, spec)
        return

    _record_port_segment(token, spec)


def _add_network_token(value: str, spec: NetworkSpec) -> None:
    """Add a normalised textual token to *spec*."""

    normalized = _normalize_token(value)
    if not normalized:
        return
    spec.tokens.add(normalized)
    if normalized in _any_tokens:
        spec.any = True


def _add_service_token(value: str, spec: ServiceSpec) -> None:
    """Add a normalised textual token to *spec*."""

    normalized = _normalize_token(value)
    if not normalized:
        return
    spec.tokens.add(normalized)
    if normalized in _any_tokens:
        spec.any = True


def _record_port_segment(segment: str, spec: ServiceSpec) -> None:
    """Parse a port or range description and update *spec*."""

    token = segment.strip()
    if not token:
        return

    lowered = token.lower()
    if lowered in {"any", "any service", "any-service"}:
        spec.any = True
        return

    if "-" in token:
        start_text, end_text = token.split("-", 1)
        start = _to_int(start_text)
        end = _to_int(end_text)
        if start is None or end is None:
            return
        if start > end:
            start, end = end, start
        spec.port_ranges.append((start, end))
        spec.tokens.add(_normalize_token(f"{start}-{end}"))
        return

    port = _to_int(token)
    if port is not None:
        spec.ports.add(port)
        spec.tokens.add(_normalize_token(str(port)))


def _normalize_protocol(value: Any) -> str:
    """Return a normalised textual representation of a protocol value."""

    text = _normalize_token(value)
    if text:
        return text
    return str(value).strip().lower()


def _to_int(value: Any) -> Optional[int]:
    """Safely convert *value* to ``int`` when possible."""

    if value in (None, ""):
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _split_tokens(value: str) -> List[str]:
    """Split a free-form string into meaningful tokens."""

    segments = re.split(r"[;,]", value)
    cleaned = [segment.strip() for segment in segments if segment.strip()]
    return cleaned or ([value] if value else [])

def _is_unused(rule: Rule) -> bool:
    """Return ``True`` when a rule appears unused."""

    has_hits = rule.hit_count is not None and rule.hit_count > 0
    has_last_hit = bool(rule.last_hit and str(rule.last_hit).strip())
    return not has_hits or not has_last_hit


def _is_overly_permissive(rule: Rule) -> bool:
    """Return ``True`` when a rule is overly permissive."""

    return (
        _normalize_token(rule.action) == "accept"
        and rule.source_spec.any
        and rule.destination_spec.any
        and rule.service_spec.any
    )


def _sort_rules_for_shadowing(rules: Sequence[Rule]) -> List[Rule]:
    """Return rules sorted by their position for shadow analysis."""

    enumerated = list(enumerate(rules))
    enumerated.sort(
        key=lambda item: (
            item[1].position is None,
            item[1].position if item[1].position is not None else item[0],
        )
    )
    return [item[1] for item in enumerated]


def _find_shadowing_rule(rule: Rule, candidates: Sequence[Rule]) -> Optional[Rule]:
    """Return the first candidate that shadows *rule*, if any."""

    for candidate in candidates:
        if _normalize_token(candidate.action) != _normalize_token(rule.action):
            continue
        if not _network_covers(candidate.source_spec, rule.source_spec):
            continue
        if not _network_covers(candidate.destination_spec, rule.destination_spec):
            continue
        if not _service_covers(candidate.service_spec, rule.service_spec):
            continue
        return candidate
    return None


def _format_unused_detail(rule: Rule) -> str:
    """Compose a detail string for unused rules."""

    parts: List[str] = []
    if rule.name:
        parts.append(f"Rule '{rule.name}'")
    else:
        parts.append(f"Rule {rule.rule_id or 'unknown'}")

    if rule.hit_count is None or rule.hit_count == 0:
        parts.append("has no recorded hits")
    if not rule.last_hit or not str(rule.last_hit).strip():
        parts.append("no last-hit timestamp")
    return ", ".join(parts)


def _format_risky_detail(rule: Rule) -> str:
    """Compose a detail string for overly permissive rules."""

    name = rule.name or rule.rule_id or "Unnamed"
    service = rule.service or "Any"
    return (
        f"Rule {name} allows any source to any destination for service '{service}'."
    )


def _format_shadow_detail(rule: Rule, shadowing_rule: Rule) -> str:
    """Compose a detail string for shadowed rules."""

    own_name = rule.name or rule.rule_id or "Unnamed"
    shadow_name = shadowing_rule.name or shadowing_rule.rule_id or "Unnamed"
    return f"Rule {own_name} is shadowed by rule {shadow_name}."


def _rule_identifier(rule: Rule) -> Union[str, int]:
    """Return a stable identifier for a rule."""

    if rule.rule_id is not None:
        return rule.rule_id
    if rule.name:
        return rule.name
    return "unknown"


def _string_value(value: Any) -> str:
    """Convert *value* into a human-readable string."""

    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (list, tuple, set)):
        return ", ".join(_string_value(item) for item in value)
    if value is None:
        return ""
    return str(value)


def _string_or_none(value: Any) -> Optional[str]:
    """Return a cleaned string or ``None`` when empty."""

    text = _string_value(value)
    return text or None


def _int_or_none(value: Any) -> Optional[int]:
    """Safely convert *value* to ``int`` when possible."""

    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _first_value(data: Dict[str, Any], *keys: str) -> Any:
    """Return the first present key value from *data*."""

    for key in keys:
        if key in data:
            return data[key]
    return None


def _normalize_token(value: Any) -> str:
    """Normalise textual tokens for comparisons."""

    text = _string_value(value).lower()
    text = text.replace("-", " ").replace("_", " ")
    return " ".join(text.split())


def _network_covers(candidate: NetworkSpec, target: NetworkSpec) -> bool:
    """Return ``True`` when *candidate* confidently covers *target*."""

    if candidate.any:
        return True
    if target.any:
        return False

    if target.addresses:
        for address in target.addresses:
            if not _address_in_spec(address, candidate):
                return False

    if target.networks:
        for network in target.networks:
            if not _network_in_spec(network, candidate):
                return False

    if target.ranges:
        for start, end in target.ranges:
            if not _range_in_spec(start, end, candidate):
                return False

    if target.tokens:
        if not target.tokens.issubset(candidate.tokens):
            return False

    if not (target.addresses or target.networks or target.ranges or target.tokens):
        return False

    return True


def _service_covers(candidate: ServiceSpec, target: ServiceSpec) -> bool:
    """Return ``True`` when *candidate* confidently covers *target*."""

    if candidate.any:
        return True
    if target.any:
        return False

    if target.protocols:
        if candidate.protocols and not target.protocols.issubset(candidate.protocols):
            return False
        if not candidate.protocols and target.protocols:
            return False

    for port in target.ports:
        if not _service_port_covered(port, candidate):
            return False

    for port_range in target.port_ranges:
        if not _service_range_covered(port_range, candidate):
            return False

    if target.tokens:
        if not target.tokens.issubset(candidate.tokens):
            return False

    if not (target.ports or target.port_ranges or target.tokens or target.protocols):
        return False

    return True


def _address_in_spec(address: IPAddress, spec: NetworkSpec) -> bool:
    """Return ``True`` when *address* is covered by *spec*."""

    for candidate in spec.addresses:
        if candidate == address:
            return True

    for network in spec.networks:
        try:
            if address.version == network.version and address in network:
                return True
        except TypeError:
            continue

    for start, end in spec.ranges:
        if address.version != start.version or address.version != end.version:
            continue
        if int(start) <= int(address) <= int(end):
            return True

    return False


def _network_in_spec(network: IPNetwork, spec: NetworkSpec) -> bool:
    """Return ``True`` when *network* is covered by *spec*."""

    for candidate in spec.networks:
        try:
            if network.subnet_of(candidate):
                return True
        except AttributeError:
            continue

    if network.prefixlen == network.max_prefixlen:
        return _address_in_spec(network.network_address, spec)

    for start, end in spec.ranges:
        if network.network_address.version != start.version:
            continue
        if int(start) <= int(network.network_address) and int(end) >= int(network.broadcast_address):
            return True

    return False


def _range_in_spec(start: IPAddress, end: IPAddress, spec: NetworkSpec) -> bool:
    """Return ``True`` when the range from *start* to *end* is covered by *spec*."""

    if start.version != end.version:
        return False

    for candidate_range in spec.ranges:
        c_start, c_end = candidate_range
        if c_start.version != start.version:
            continue
        if int(c_start) <= int(start) and int(c_end) >= int(end):
            return True

    if start == end:
        return _address_in_spec(start, spec)

    for network in spec.networks:
        if network.network_address.version != start.version:
            continue
        if int(network.network_address) <= int(start) and int(network.broadcast_address) >= int(end):
            return True

    return False


def _service_port_covered(port: int, spec: ServiceSpec) -> bool:
    """Return ``True`` when *port* is within the coverage of *spec*."""

    if port in spec.ports:
        return True

    for start, end in spec.port_ranges:
        if start <= port <= end:
            return True

    return False


def _service_range_covered(port_range: Tuple[int, int], spec: ServiceSpec) -> bool:
    """Return ``True`` when *port_range* is fully covered by *spec*."""

    start, end = port_range
    if start > end:
        start, end = end, start

    for candidate_start, candidate_end in spec.port_ranges:
        if candidate_start <= start and candidate_end >= end:
            return True

    if start == end and start in spec.ports:
        return True

    return False
