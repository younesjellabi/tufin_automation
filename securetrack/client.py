"""Client for interacting with the Tufin SecureTrack APIs."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlsplit

import requests
try:
    import xmltodict
except ImportError:  # pragma: no cover - optional dependency
    xmltodict = None  # type: ignore

from requests import Response, Session
from requests.auth import HTTPBasicAuth

try:  # pragma: no cover - optional dependency import
    from pytos2.api import ApiError
    from pytos2.securetrack.entrypoint import St
except ImportError:  # pragma: no cover - SDK is optional
    ApiError = Exception  # type: ignore
    St = None  # type: ignore


class SecureTrackClientError(RuntimeError):
    """Base exception for SecureTrack API client errors."""


class SecureTrackClient:
    """Client for making requests to the SecureTrack API and SDK.

    Parameters
    ----------
    base_url:
        Base URL of the SecureTrack server, e.g. ``"https://securetrack.example.com"``.
    username:
        Username used for authentication.
    password:
        Password used for authentication.
    session:
        Optional pre-configured :class:`requests.Session` instance. When omitted a
        new session is created automatically.
    timeout:
        Default timeout (in seconds) used for all HTTP requests.
    verify:
        SSL certificate verification flag passed to :func:`requests.Session.request`.
    use_sdk:
        When ``True`` (default) the official ``pytos2-ce`` SDK is leveraged for
        rule retrieval, falling back to direct REST calls if the SDK is
        unavailable or fails.
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
        use_sdk: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.headers.update({"Accept": "application/json, */*"})
        self.timeout = timeout
        self.verify = verify

        self._sdk = None
        self._sdk_error: Optional[Exception] = None
        if use_sdk and St is not None:
            try:
                sdk_host = self._sanitize_sdk_hostname(self.base_url)
                self._sdk = St(
                    hostname=sdk_host,
                    username=username,
                    password=password,
                    default=False,
                )
                self._sdk.api.session.verify = verify
            except Exception as exc:  # pragma: no cover - depends on SDK/runtime
                self._sdk = None
                self._sdk_error = exc

    def get_rules(self, device: Optional[Union[str, int]] = None) -> Any:
        """Retrieve rules from SecureTrack.

        Parameters
        ----------
        device:
            Optional device identifier or name whose rules should be returned.

        Returns
        -------
        Any
            Parsed response (typically JSON) containing rule information.

        Raises
        ------
        SecureTrackClientError
            If both SDK and REST retrieval attempts fail.
        """

        sdk_exc: Optional[Exception] = None
        if self._sdk is not None:
            try:
                rules = self._sdk.get_rules(device=device, cache=False)
                return [self._rule_to_dict(rule) for rule in rules]
            except ApiError as exc:  # pragma: no cover - network-dependent
                sdk_exc = exc
                self._sdk_error = exc

        params: Dict[str, Any] = {}
        if device is not None:
            params["deviceId"] = str(device)

        try:
            return self._request("GET", self._RULES_ENDPOINT, params=params or None)
        except SecureTrackClientError as rest_exc:
            if sdk_exc is not None:
                message = (
                    "SecureTrack SDK and REST requests failed while retrieving rules. "
                    f"SDK error: {sdk_exc}. REST error: {rest_exc}"
                )
                raise SecureTrackClientError(message) from rest_exc
            raise

    def get_logs(
        self,
        *,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Fetch traffic logs from SecureTrack."""

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
        """Perform a connectivity check between two endpoints."""

        payload = {
            "source": source_ip,
            "destination": dest_ip,
            "service": service,
        }
        return self._request("POST", self._CONNECTIVITY_ENDPOINT, json=payload)


    def check_connection(self) -> Dict[str, Any]:
        """Perform a lightweight connectivity test against SecureTrack."""

        result: Dict[str, Any] = {
            "base_url": self.base_url,
            "sdk_available": self._sdk is not None,
        }

        sample_device = None
        if self._sdk is not None:
            try:
                devices = self._sdk.get_devices(cache=False)
                result["sdk_status"] = "ok"
                sample_device = self._sample_from_devices(devices)
                if sample_device:
                    result["sample_device"] = sample_device
                    result["status"] = "ok"
                    result["via"] = "sdk"
                    return result
            except ApiError as exc:  # pragma: no cover - depends on SDK availability
                self._sdk_error = exc
                result["sdk_status"] = "error"
                result["sdk_error"] = str(exc)

        try:
            payload = self._request(
                "GET",
                "/securetrack/api/devices",
                params={"limit": 1},
            )
            result["rest_status"] = "ok"
            if sample_device is None:
                sample_device = self._sample_from_payload(payload)
                if sample_device:
                    result["sample_device"] = sample_device
            result["status"] = "ok"
            result.setdefault("via", "rest")
            return result
        except SecureTrackClientError as exc:
            result["rest_status"] = "error"
            result["rest_error"] = str(exc)
            if self._sdk_error is not None:
                result["sdk_error"] = str(self._sdk_error)
            detail = json.dumps(result, indent=2)
            raise SecureTrackClientError(
                f"SecureTrack connectivity test failed. Details: {detail}"
            ) from exc

    @staticmethod
    def _sample_from_devices(devices: Any) -> Optional[Dict[str, Any]]:
        """Extract a representative device from an SDK device collection."""

        candidate = None
        if isinstance(devices, list):
            candidate = devices[0] if devices else None
        else:  # fall back to iterator semantics
            iterator = iter(devices) if hasattr(devices, "__iter__") else None
            if iterator is not None:
                try:
                    candidate = next(iterator)
                except StopIteration:
                    candidate = None

        if candidate is None:
            return None

        json_payload = getattr(candidate, "_json", None)
        if isinstance(json_payload, dict):
            return {
                "id": json_payload.get("id") or getattr(candidate, "id", None),
                "name": json_payload.get("name") or getattr(candidate, "name", None),
                "vendor": json_payload.get("vendor") or getattr(candidate, "vendor", None),
            }

        return {
            "id": getattr(candidate, "id", None),
            "name": getattr(candidate, "name", None),
            "vendor": getattr(candidate, "vendor", None),
        }

    @staticmethod
    def _sample_from_payload(payload: Any) -> Optional[Dict[str, Any]]:
        """Extract a representative device entry from a REST payload."""

        items: Optional[List[Dict[str, Any]]] = None

        if isinstance(payload, list):
            items = [item for item in payload if isinstance(item, dict)]
        elif isinstance(payload, dict):
            for key in ("devices", "results", "items", "data"):
                value = payload.get(key)
                if isinstance(value, list):
                    items = [item for item in value if isinstance(item, dict)]
                    if items:
                        break
                if isinstance(value, dict):
                    for sub_key in ("device", "items", "results"):
                        inner = value.get(sub_key)
                        if isinstance(inner, list):
                            items = [item for item in inner if isinstance(item, dict)]
                            if items:
                                break
                    if items:
                        break

        if not items:
            return None

        sample = items[0]
        return {
            "id": sample.get("id") or sample.get("deviceId"),
            "name": sample.get("name") or sample.get("device"),
            "vendor": sample.get("vendor"),
        }

    def path_lookup(
        self,
        source_ip: str,
        dest_ip: str,
        service: Optional[str] = None,
    ) -> Any:
        """Retrieve SecureTrack path analysis for the given traffic flow."""

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
        """Execute an HTTP request and return a parsed representation."""

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

        content_type = (response.headers.get("Content-Type") or "").lower()
        text = response.text

        if "json" in content_type:
            try:
                return response.json()
            except ValueError as exc:  # pragma: no cover - server misbehaviour
                raise SecureTrackClientError(
                    f"Invalid JSON response returned from {url}"
                ) from exc

        if "xml" in content_type or text.lstrip().startswith("<?xml"):
            if xmltodict is None:
                return text
            try:
                return xmltodict.parse(text)
            except Exception as exc:  # pragma: no cover - server misbehaviour
                raise SecureTrackClientError(
                    f"Invalid XML response returned from {url}"
                ) from exc

        try:
            return response.json()
        except ValueError:
            return text

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

    @staticmethod
    def _sanitize_sdk_hostname(url: str) -> str:
        """Collapse *url* to a scheme+host value suitable for the SDK."""

        parts = urlsplit(url)
        if parts.scheme and parts.netloc:
            return f"{parts.scheme}://{parts.netloc}"
        return url

    @staticmethod
    def _rule_to_dict(rule: Any) -> Dict[str, Any]:
        """Convert a ``pytos2`` SecurityRule into a plain dictionary."""

        data: Dict[str, Any] = {}
        raw = getattr(rule, "_json", None)
        if isinstance(raw, dict):
            data.update(raw)

        rule_id = getattr(rule, "id", None)
        if rule_id is not None:
            data.setdefault("id", rule_id)
            data.setdefault("ruleId", rule_id)

        uid = getattr(rule, "uid", None)
        if uid is not None:
            data.setdefault("uid", uid)

        device_obj = getattr(rule, "device", None)
        if device_obj is not None:
            device_json = getattr(device_obj, "_json", None)
            if isinstance(device_json, dict):
                name = device_json.get("name")
                identifier = device_json.get("id")
                if name is not None:
                    data.setdefault("device", name)
                    data.setdefault("deviceName", name)
                if identifier is not None:
                    data.setdefault("device_id", identifier)
                    data.setdefault("deviceId", identifier)
            else:
                name = getattr(device_obj, "name", None)
                identifier = getattr(device_obj, "id", None)
                if name is not None:
                    data.setdefault("device", name)
                    data.setdefault("deviceName", name)
                if identifier is not None:
                    data.setdefault("device_id", identifier)
                    data.setdefault("deviceId", identifier)

        return data



