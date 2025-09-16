# Tufin SecureTrack Troubleshooting & Auditing Toolkit

This project provides a modular toolkit for automating routine SecureTrack operations such as auditing rules, analyzing traffic logs, running connectivity checks, and performing path lookups. It is designed as a foundation for building richer workflows and CLI automation around the SecureTrack REST API.

## Features
- Reusable `SecureTrackClient` that wraps SecureTrack REST endpoints using a persistent `requests.Session`
- Structured error handling with a custom exception type for clearer troubleshooting
- Extensible package layout intended to grow into a full CLI with subcommands for rule auditing, log analysis, connectivity checks, and path lookup reporting

## Installation
1. (Optional) Create and activate a virtual environment.
2. Install the project dependencies:
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
)

rules = client.get_rules()
logs = client.get_logs(start_time="2024-01-01T00:00:00Z", end_time="2024-01-02T00:00:00Z")
connectivity = client.connectivity_check("10.0.0.10", "172.16.0.5", "tcp/443")
path = client.path_lookup("10.0.0.10", "172.16.0.5")
```

Additional CLI tooling and automated analyses will be layered on top of this client in future iterations.

## Development
- Code targets Python 3.8+ and follows PEP 8 guidelines.
- Run `python -m compileall securetrack` to perform a basic syntax check.

Contributions and feature requests are welcome as the toolkit evolves.
