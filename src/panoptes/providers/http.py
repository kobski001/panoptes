
from __future__ import annotations

from typing import Any

import requests


def map_http_status(status_code: int) -> str:
    """Map HTTP status codes to our application's provider statuses."""
    if 200 <= status_code < 300:
        return "success"
    if status_code == 401:
        return "auth_error"
    if status_code == 403:
        return "permission_error"
    if status_code == 404:
        return "no_data"
    if status_code == 429:
        return "rate_limited"
    return "error"


class HttpClient:
    """Small HTTP client with consistent timeout and error handling."""

    def __init__(self, timeout_seconds: float = 10.0) -> None:
        self.timeout_seconds = timeout_seconds
        self.session = requests.Session()

    def get_json(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
    ) -> tuple[str, dict[str, Any], str | None]:
        """Return (status, JSON payload, safe error message)."""
        try:
            response = self.session.get(
                url,
                headers=headers,
                params=params,
                timeout=self.timeout_seconds,
            )
        except requests.Timeout:
            return "timeout", {}, "The provider request timed out."
        except requests.RequestException:
            return "error", {}, "The provider request failed."

        status = map_http_status(response.status_code)

        if status != "success":
            return status, {}, f"Provider returned HTTP {response.status_code}."

        try:
            payload = response.json()
        except requests.exceptions.JSONDecodeError:
            return "error", {}, "Provider returned invalid JSON."

        if not isinstance(payload, dict):
            return "error", {}, "Provider returned an unexpected JSON structure."

        return "success", payload, None
