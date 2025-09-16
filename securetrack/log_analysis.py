"""Helper utilities for SecureTrack traffic log analysis."""
from __future__ import annotations

from typing import Any, Dict, Optional

from .client import SecureTrackClient

__all__ = ["run_log_analysis"]


def run_log_analysis(
    client: SecureTrackClient,
    *,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    filters: Optional[Dict[str, Any]] = None,
    summary_only: bool = False,
) -> Any:
    """Retrieve logs from SecureTrack and optionally summarize them."""

    logs = client.get_logs(
        start_time=start_time,
        end_time=end_time,
        filters=filters,
    )

    if not summary_only:
        return logs

    return _summarize_logs(logs)


def _summarize_logs(logs: Any) -> Dict[str, Any]:
    """Provide a basic summary for the returned log payload."""

    if isinstance(logs, list):
        return {"log_count": len(logs)}

    if isinstance(logs, dict):
        summary: Dict[str, Any] = {"fields": sorted(logs.keys())}
        entries = logs.get("logs")
        if isinstance(entries, list):
            summary["log_count"] = len(entries)
        return summary

    return {"detail": "Summary unavailable for the returned payload."}
