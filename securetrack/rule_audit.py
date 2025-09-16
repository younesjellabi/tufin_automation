"""Helper utilities for SecureTrack rule auditing workflows."""
from __future__ import annotations

import csv
from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, TextIO, Union

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

_any_tokens = {"any", "any service", "any-service", "anyservice"}


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

    return Rule(
        rule_id=_first_value(data, "id", "ruleId", "rule_id", "uid", "ruleUid"),
        name=_string_or_none(
            _first_value(data, "name", "ruleName", "displayName", "label")
        ),
        device=_string_or_none(
            _first_value(data, "device_name", "deviceName", "device", "gateway")
        ),
        action=_string_value(_first_value(data, "action", "ruleAction") or ""),
        source=_string_value(
            _first_value(data, "source", "sources", "source_text", "src") or ""
        ),
        destination=_string_value(
            _first_value(
                data,
                "destination",
                "dest",
                "destinations",
                "destination_text",
                "dst",
            )
            or ""
        ),
        service=_string_value(
            _first_value(data, "service", "services", "application", "svc") or ""
        ),
        hit_count=_int_or_none(
            _first_value(data, "hit_count", "hitCount", "hits", "usageCount")
        ),
        last_hit=_string_or_none(
            _first_value(data, "last_hit", "lastHit", "last_hit_time", "lastUsed")
        ),
        position=position,
        raw=data,
    )


def _is_unused(rule: Rule) -> bool:
    """Return ``True`` when a rule appears unused."""

    has_hits = rule.hit_count is not None and rule.hit_count > 0
    has_last_hit = bool(rule.last_hit and str(rule.last_hit).strip())
    return not has_hits or not has_last_hit


def _is_overly_permissive(rule: Rule) -> bool:
    """Return ``True`` when a rule is overly permissive."""

    return (
        _normalize_token(rule.action) == "accept"
        and _is_any_network(rule.source)
        and _is_any_network(rule.destination)
        and _is_any_service(rule.service)
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
        if not _network_covers(candidate.source, rule.source):
            continue
        if not _network_covers(candidate.destination, rule.destination):
            continue
        if not _service_covers(candidate.service, rule.service):
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


def _is_any_network(value: str) -> bool:
    """Return ``True`` if *value* represents any network."""

    return _normalize_token(value) in _any_tokens


def _is_any_service(value: str) -> bool:
    """Return ``True`` if *value* represents an unrestricted service."""

    return _normalize_token(value) in _any_tokens


def _network_covers(earlier: str, later: str) -> bool:
    """Return ``True`` when *earlier* matches or includes *later*."""

    if _is_any_network(earlier):
        return True
    return _normalize_token(earlier) == _normalize_token(later)


def _service_covers(earlier: str, later: str) -> bool:
    """Return ``True`` when the service definition in *earlier* covers *later*."""

    if _is_any_service(earlier):
        return True
    return _normalize_token(earlier) == _normalize_token(later)
