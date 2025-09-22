"""Public entry point for the SecureTrack client."""
from __future__ import annotations

from securetrack import SecureTrackClient, SecureTrackClientError

import os

__all__ = ["SecureTrackClient", "SecureTrackClientError"]

try:
    from dotenv import load_dotenv  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    load_dotenv = None  # type: ignore

if __name__ == "__main__":  # pragma: no cover - manual connectivity helper
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(
        description="Quick SecureTrack connectivity test",
    )
    if load_dotenv:
        load_dotenv()

    default_server = os.getenv("SECURETRACK_SERVER")
    default_user = os.getenv("SECURETRACK_USER")
    default_password = os.getenv("SECURETRACK_PASSWORD")

    parser.add_argument(
        "--server",
        default=default_server,
        required=default_server is None,
        help="SecureTrack server URL (or SECURETRACK_SERVER)",
    )
    parser.add_argument(
        "--user",
        default=default_user,
        required=default_user is None,
        help="API username (or SECURETRACK_USER)",
    )
    parser.add_argument(
        "--password",
        default=default_password,
        required=default_password is None,
        help="API password (or SECURETRACK_PASSWORD)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout in seconds for API requests",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate validation",
    )
    parser.add_argument(
        "--no-sdk",
        action="store_true",
        help="Do not attempt to use the pytos2 SDK",
    )

    args = parser.parse_args()
    client = SecureTrackClient(
        base_url=args.server,
        username=args.user,
        password=args.password,
        timeout=args.timeout,
        verify=not args.insecure,
        use_sdk=not args.no_sdk,
    )
    try:
        status = client.check_connection()
    except SecureTrackClientError as exc:
        print(f"Connectivity test failed: {exc}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(status, indent=2))
    sys.exit(0)
