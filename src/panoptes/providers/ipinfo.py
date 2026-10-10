
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any

from panoptes.models import ProviderResult
from panoptes.providers.base import BaseProvider
from panoptes.providers.http import HttpClient


class IPInfoProvider(BaseProvider):
    """Passive IP intelligence lookup using IPinfo Lite."""

    name = "ipinfo_lite"
    BASE_URL = "https://api.ipinfo.io/lite"

    def __init__(
        self,
        token: str | None = None,
        client: HttpClient | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.token = token if token is not None else os.getenv("IPINFO_TOKEN")
        self.client = client or HttpClient(timeout_seconds)
        self.ttl = timedelta(hours=24)

    def normalize(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Map IPinfo Lite fields into our shared schema."""
        return {
            "ip_address": payload.get("ip"),
            "asn": payload.get("asn"),
            "organization": payload.get("as_name"),
            "as_domain": payload.get("as_domain"),
            "country_code": payload.get("country_code"),
            "country_name": payload.get("country"),
            "continent_code": payload.get("continent_code"),
            "continent_name": payload.get("continent"),
        }

    def lookup(self, ip_address: str) -> ProviderResult:
        retrieved_at = datetime.now(timezone.utc)

        if not self.token:
            return ProviderResult(
                provider=self.name,
                status="auth_error",
                retrieved_at=retrieved_at,
                error_code="missing_api_token",
                error_message="IPinfo token is not configured.",
            )

        status, payload, error = self.client.get_json(
            f"{self.BASE_URL}/{ip_address}",
            params={"token": self.token},
        )

        if status != "success":
            return ProviderResult(
                provider=self.name,
                status=status,
                retrieved_at=retrieved_at,
                error_code=status,
                error_message=error,
            )

        if not payload.get("ip"):
            return ProviderResult(
                provider=self.name,
                status="error",
                retrieved_at=retrieved_at,
                error_code="unexpected_payload",
                error_message="IPinfo response did not include an IP address.",
            )

        return ProviderResult(
            provider=self.name,
            status="success",
            retrieved_at=retrieved_at,
            expires_at=retrieved_at + self.ttl,
            normalized_data=self.normalize(payload),
            raw_data=payload,
        )
