"""Command-line interface for the Tufin SecureTrack automation toolkit."""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, TextIO

from tufin_client import SecureTrackClient, SecureTrackClientError

from securetrack.log_analysis import run_log_analysis
from securetrack.rule_audit import run_rule_audit


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the top-level argument parser."""

    parser = argparse.ArgumentParser(
        description="CLI utilities for interacting with Tufin SecureTrack.",
    )
    parser.add_argument("--server", required=True, help="SecureTrack server URL")
    parser.add_argument("--user", required=True, help="Username for authentication")
    parser.add_argument("--password", required=True, help="Password for authentication")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout for HTTP requests in seconds",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    _add_rule_audit_parser(subparsers)
    _add_log_analysis_parser(subparsers)
    _add_connectivity_parser(subparsers)
    _add_path_lookup_parser(subparsers)

    return parser


def _add_rule_audit_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the rule-audit subcommand."""

    parser = subparsers.add_parser(
        "rule-audit", help="Audit SecureTrack rules for a device"
    )
    parser.add_argument("--device-id", help="Filter rules by device identifier")
    _add_output_arguments(parser, {"json", "csv", "text"})
    parser.set_defaults(handler=_handle_rule_audit)


def _add_log_analysis_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register the log-analysis subcommand."""

    parser = subparsers.add_parser(
        "log-analysis", help="Analyze traffic logs retrieved from SecureTrack"
    )
    parser.add_argument("--start", help="ISO8601 start timestamp")
    parser.add_argument("--end", help="ISO8601 end timestamp")
    parser.add_argument("--src", help="Source IP address filter")
    parser.add_argument("--dst", help="Destination IP address filter")
    parser.add_argument("--protocol", help="Protocol filter")
    parser.add_argument("--rule", dest="rule_id", help="Rule identifier filter")
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Return only summary information for the requested timeframe",
    )
    _add_output_arguments(parser, {"json", "csv", "text"})
    parser.set_defaults(handler=_handle_log_analysis)


def _add_connectivity_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register the connectivity-check subcommand."""

    parser = subparsers.add_parser(
        "connectivity-check",
        help="Perform a connectivity check between two endpoints",
    )
    parser.add_argument("--src", required=True, help="Source IP address")
    parser.add_argument("--dst", required=True, help="Destination IP address")
    parser.add_argument("--service", required=True, help="Service or port to test")
    _add_output_arguments(parser, {"json", "text"})
    parser.set_defaults(handler=_handle_connectivity)


def _add_path_lookup_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register the path-lookup subcommand."""

    parser = subparsers.add_parser(
        "path-lookup",
        help="Retrieve SecureTrack path analysis for a traffic flow",
    )
    parser.add_argument("--src", required=True, help="Source IP address")
    parser.add_argument("--dst", required=True, help="Destination IP address")
    parser.add_argument("--service", help="Optional service or application name")
    _add_output_arguments(parser, {"json", "csv", "text"})
    parser.set_defaults(handler=_handle_path_lookup)


def _add_output_arguments(
    parser: argparse.ArgumentParser, choices: Iterable[str]
) -> None:
    """Attach standard output arguments to a subcommand parser."""

    parser.add_argument(
        "--output",
        choices=sorted(choices),
        default="json",
        help="Output format",
    )
    parser.add_argument(
        "--out-file",
        type=Path,
        help="Optional path to write the output; defaults to stdout",
    )


def _handle_rule_audit(client: SecureTrackClient, args: argparse.Namespace) -> Any:
    """Execute the rule-audit workflow and return structured data."""

    return run_rule_audit(client, device_id=args.device_id)


def _handle_log_analysis(client: SecureTrackClient, args: argparse.Namespace) -> Any:
    """Execute the log-analysis workflow and return structured data."""

    filters: Dict[str, Any] = {}
    if args.src:
        filters["source_ip"] = args.src
    if args.dst:
        filters["destination_ip"] = args.dst
    if args.protocol:
        filters["protocol"] = args.protocol
    if args.rule_id:
        filters["rule_id"] = args.rule_id

    return run_log_analysis(
        client,
        start_time=args.start,
        end_time=args.end,
        filters=filters or None,
        summary_only=args.summary_only,
    )


def _handle_connectivity(client: SecureTrackClient, args: argparse.Namespace) -> Any:
    """Trigger a connectivity check via the SecureTrack client."""

    return client.connectivity_check(args.src, args.dst, args.service)


def _handle_path_lookup(client: SecureTrackClient, args: argparse.Namespace) -> Any:
    """Trigger a path lookup via the SecureTrack client."""

    return client.path_lookup(args.src, args.dst, service=args.service)


def _output_result(data: Any, fmt: str, path: Optional[Path]) -> None:
    """Serialize *data* to the requested format at the provided destination."""

    stream: TextIO
    should_close = False
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        stream = path.open("w", encoding="utf-8")
        should_close = True
    else:
        stream = sys.stdout

    try:
        if fmt == "json":
            json.dump(data, stream, indent=2)
            stream.write("\n")
        elif fmt == "csv":
            _write_csv(data, stream)
        elif fmt == "text":
            _write_text(data, stream)
        else:  # pragma: no cover - safeguarded by argparse choices
            raise ValueError(f"Unsupported output format: {fmt}")
    finally:
        if should_close:
            stream.close()


def _write_csv(data: Any, stream: TextIO) -> None:
    """Write *data* as CSV, accepting flat dicts or sequences of flat dicts."""

    if isinstance(data, dict):
        _write_csv_from_dict(data, stream)
        return
    if isinstance(data, list):
        _write_csv_from_list(data, stream)
        return
    raise ValueError(
        "CSV output supports only dictionaries or lists of dictionaries. "
        "Please use JSON output for nested data structures."
    )


def _write_csv_from_dict(row: Dict[str, Any], stream: TextIO) -> None:
    """Emit a one-row CSV from a flat dictionary."""

    if not _is_flat_row(row):
        raise ValueError(
            "CSV output supports only flat dictionaries. Please choose JSON output."
        )
    writer = csv.DictWriter(stream, fieldnames=list(row.keys()))
    writer.writeheader()
    writer.writerow(row)


def _write_csv_from_list(rows: List[Any], stream: TextIO) -> None:
    """Emit CSV output from a list of dictionaries."""

    if not rows:
        raise ValueError("No rows available for CSV export.")

    candidate_rows: List[Dict[str, Any]] = []
    for item in rows:
        if isinstance(item, dict) and _is_flat_row(item):
            candidate_rows.append(item)
        else:
            raise ValueError(
                "CSV output requires a list of flat dictionaries. Please choose JSON output."
            )

    fieldnames = sorted({key for row in candidate_rows for key in row})
    writer = csv.DictWriter(stream, fieldnames=fieldnames)
    writer.writeheader()
    for row in candidate_rows:
        writer.writerow({name: row.get(name, "") for name in fieldnames})


def _is_flat_row(row: Dict[str, Any]) -> bool:
    """Return True when *row* contains only scalar values."""

    return all(not isinstance(value, (dict, list, tuple, set)) for value in row.values())


def _write_text(data: Any, stream: TextIO) -> None:
    """Render a compact text summary of *data*."""

    for line in _format_text_summary(data):
        stream.write(f"{line}\n")


def _format_text_summary(data: Any) -> List[str]:
    """Create a condensed textual representation for display."""

    if data is None:
        return ["No data returned."]

    if isinstance(data, list):
        lines = [f"Items returned: {len(data)}"]
        preview = data[:5]
        for item in preview:
            lines.append(_summarize_item(item))
        if len(data) > len(preview):
            lines.append("… output truncated; consider JSON for full details …")
        return lines

    if isinstance(data, dict):
        return [_summarize_dict(data)]

    return [str(data)]


def _summarize_item(item: Any) -> str:
    """Summarize a list entry for text output."""

    if isinstance(item, dict):
        parts = [f"{key}={value}" for key, value in list(item.items())[:5]]
        return "- " + ", ".join(parts)
    return f"- {item}"


def _summarize_dict(data: Dict[str, Any]) -> str:
    """Summarize a dictionary for text output."""

    parts = [f"{key}={value}" for key, value in list(data.items())[:8]]
    if len(data) > 8:
        parts.append("…")
    return ", ".join(parts)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point for the SecureTrack CLI."""

    parser = create_parser()
    args = parser.parse_args(argv)
    client = SecureTrackClient(
        base_url=args.server,
        username=args.user,
        password=args.password,
        timeout=args.timeout,
        verify=not args.insecure,
    )

    handler = getattr(args, "handler", None)
    if handler is None:
        parser.error("No subcommand provided")  # pragma: no cover - argparse enforces

    try:
        result = handler(client, args)
        _output_result(result, args.output, args.out_file)
    except SecureTrackClientError as exc:
        print(f"SecureTrack API error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except Exception as exc:  # pragma: no cover - safeguard for unexpected issues
        print(f"Unexpected error: {exc}", file=sys.stderr)
        return 1

    return 0


def run() -> None:
    """Convenience wrapper to execute the CLI."""

    sys.exit(main())


if __name__ == "__main__":
    run()
