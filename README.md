# Tufin SecureTrack Troubleshooting & Auditing Toolkit

This project provides a modular toolkit for automating routine SecureTrack operations such as auditing rules, analyzing traffic logs, running connectivity checks, and performing path lookups. It is designed as a foundation for building richer workflows and CLI automation around the SecureTrack REST API and the official `pytos2-ce` SDK.

## Features
- Reusable `SecureTrackClient` that wraps SecureTrack REST endpoints and, when available, leverages the `pytos2-ce` SDK for richer rule retrieval while falling back to raw REST calls as needed
- Structured error handling with a custom exception type for clearer troubleshooting
- Extensible package layout intended to grow into a full CLI with subcommands for rule auditing, log analysis, connectivity checks, and path lookup reporting
- CLI flag (`--no-sdk`) to force REST-only behaviour when the SDK cannot be used
- Quick `health-check` command for smoke-testing credentials and API reachability

## Installation
1. (Optional) Create and activate a virtual environment.
2. Install the project dependencies (Python 3.10+ required for `pytos2-ce`):
   ```bash
   pip install -r requirements.txt
   ```

## Usage
Instantiate the client with your SecureTrack credentials and base URL, then call the desired helper methods.

```python
from securetrack import SecureTrackClient

client = SecureTrackClient(
    base_url="https://securetrack.example.com",
    username="api-user",
    password="s3cret",
    use_sdk=True,  # Disable with False or CLI --no-sdk if the SDK is unavailable
)

status = client.check_connection()
print(status["status"], status.get("sample_device"))

rules = client.get_rules()
logs = client.get_logs(start_time="2024-01-01T00:00:00Z", end_time="2024-01-02T00:00:00Z")
connectivity = client.connectivity_check("10.0.0.10", "172.16.0.5", "tcp/443")
path = client.path_lookup("10.0.0.10", "172.16.0.5")
```

The CLI mirrors these capabilities; run `python -m securetrack.cli --help` for details. For a quick reachability test, use `python -m securetrack.cli --server <url> --user <user> --password <pass> health-check`. Use `--no-sdk` to force REST-only calls if you cannot or do not wish to install `pytos2-ce`.

## Environment configuration
Create a `.env` file alongside this project (or export environment variables) with your SecureTrack connection details:

```env
SECURETRACK_SERVER=https://securetrack.example.com
SECURETRACK_USER=api-user
SECURETRACK_PASSWORD=s3cret
```

Both the Python helper and CLI automatically load these values via `python-dotenv`. Command-line flags still override the environment when provided.

## Development
- Code targets Python 3.10+ and follows PEP 8 guidelines.
- Run `python -m compileall securetrack` to perform a basic syntax check.

Contributions and feature requests are welcome as the toolkit evolves.

