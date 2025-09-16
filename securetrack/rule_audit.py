"""Helper utilities for SecureTrack rule auditing workflows."""
from __future__ import annotations

from typing import Any, Optional

from .client import SecureTrackClient

__all__ = ["run_rule_audit"]


def run_rule_audit(
    client: SecureTrackClient,
    *,
    device_id: Optional[str] = None,
) -> Any:
    """Return rule data fetched from SecureTrack.

    This function currently proxies to :meth:`SecureTrackClient.get_rules` and
    exists as an extension point for richer auditing capabilities to be added
    later on.
    """

    return client.get_rules(device_id=device_id)
