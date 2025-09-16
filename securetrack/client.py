"""Client for interacting with the Tufin SecureTrack REST API."""
from __future__ import annotations

from typing import Any, Dict, Optional

import requests
from requests import Response, Session
from requests.auth import HTTPBasicAuth


class SecureTrackClientError(RuntimeError):
    """Base exception for SecureTrack API client errors."""


class SecureTrackClient:
    """Client for making requests to the SecureTrack API.

    Parameters
    ----------
    base_url:
        The base URL of the SecureTrack server, for example
        ``"https://securetrack.example.com"``.
    username:
        The username used for HTTP basic authentication.
    password:
        The password used for HTTP basic authentication.
    session:
        Optional pre-configured :class:`requests.Session` instance. When not
        provided a new session is created automatically.
    timeout:
        Default timeout (in seconds) used for all HTTP requests.
    verify:
        SSL certificate verification flag passed to :func:`requests.Session.request`.
    """

    _RULES_ENDPOINT = "/securetrack/api/rules"
    _LOGS_ENDPOINT = "/securetrack/api/logs"
    _CONNECTIVITY_ENDPOINT = "/securetrack/api/connectivity-check"
    _PATH_LOOKUP_ENDPOINT = "/securetrack/api/path-lookup"

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        session: Optional[Session] = None,
        timeout: Optional[int] = 30,
        verify: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.headers.update({"Accept": "application/json"})
        self.timeout = timeout
        self.verify = verify

    def get_rules(self, device_id: Optional[str] = None) -> Any:
        """Retrieve rules from SecureTrack.

        Parameters
        ----------
        device_id:
            Optional identifier of the device whose rules should be returned.

        Returns
        -------
        Any
            Parsed JSON response from the API containing rule information.

        Raises
        ------
        SecureTrackClientError
            If the API request fails or returns invalid JSON.
        """

        params: Dict[str, Any] = {}
        if device_id:
            params["deviceId"] = device_id
        return self._request("GET", self._RULES_ENDPOINT, params=params or None)

    def get_logs(
        self,
        *,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Fetch traffic logs from SecureTrack.

        Parameters
        ----------
        start_time:
            Optional start timestamp (ISO 8601 string) for log retrieval.
        end_time:
            Optional end timestamp (ISO 8601 string) for log retrieval.
        filters:
            Additional filter parameters, such as source or destination IPs,
            protocol, or rule identifiers.

        Returns
        -------
        Any
            Parsed JSON response from the API containing log entries.

        Raises
        ------
        SecureTrackClientError
            If the API request fails or returns invalid JSON.
        """

        params: Dict[str, Any] = {}
        if start_time:
            params["start_time"] = start_time
        if end_time:
            params["end_time"] = end_time
        if filters:
            params.update(filters)
        return self._request("GET", self._LOGS_ENDPOINT, params=params or None)

    def connectivity_check(
        self, source_ip: str, dest_ip: str, service: str
    ) -> Any:
        """Perform a connectivity check between two endpoints.

        Parameters
        ----------
        source_ip:
            Source IP address for the connectivity query.
        dest_ip:
            Destination IP address for the connectivity query.
        service:
            Network service (such as a port number or service name) to evaluate.

        Returns
        -------
        Any
            Parsed JSON response describing whether the connection is allowed or
            blocked, including the matching rule when available.

        Raises
        ------
        SecureTrackClientError
            If the API request fails or returns invalid JSON.
        """

        payload = {
            "source": source_ip,
            "destination": dest_ip,
            "service": service,
        }
        return self._request("POST", self._CONNECTIVITY_ENDPOINT, json=payload)

    def path_lookup(
        self,
        source_ip: str,
        dest_ip: str,
        service: Optional[str] = None,
    ) -> Any:
        """Retrieve SecureTrack path analysis for the given traffic flow.

        Parameters
        ----------
        source_ip:
            Source IP address for the path lookup.
        dest_ip:
            Destination IP address for the path lookup.
        service:
            Optional service identifier (port or application) to refine the
            analysis.

        Returns
        -------
        Any
            Parsed JSON response describing devices, interfaces, and policies
            traversed by the evaluated traffic.

        Raises
        ------
        SecureTrackClientError
            If the API request fails or returns invalid JSON.
        """

        payload = {
            "source": source_ip,
            "destination": dest_ip,
        }
        if service is not None:
            payload["service"] = service
        return self._request("POST", self._PATH_LOOKUP_ENDPOINT, json=payload)

    def _request(
        self,
        method: str,
        endpoint: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Execute an HTTP request and return the parsed JSON response."""

        url = f"{self.base_url}{endpoint}"
        try:
            response = self.session.request(
                method,
                url,
                params=params,
                json=json,
                timeout=self.timeout,
                verify=self.verify,
            )
            self._raise_for_status(response)
        except requests.RequestException as exc:  # pragma: no cover - network failure
            raise SecureTrackClientError(
                f"Failed to communicate with SecureTrack API: {exc}"
            ) from exc

        if not response.content:
            return None

        try:
            return response.json()
        except ValueError as exc:  # pragma: no cover - depends on server response
            raise SecureTrackClientError(
                f"Invalid JSON response returned from {url}"
            ) from exc

    @staticmethod
    def _raise_for_status(response: Response) -> None:
        """Raise a :class:`SecureTrackClientError` for HTTP error responses."""

        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            detail = None
            try:
                detail = response.json()
            except ValueError:
                detail = response.text or None

            message = (
                f"SecureTrack API responded with status "
                f"{response.status_code}: {detail or 'No details provided.'}"
            )
            raise SecureTrackClientError(message) from exc
