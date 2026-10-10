from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from panoptes.models import ProviderResult
from panoptes.providers.base import BaseProvider
from panoptes.providers.http import HttpClient


class ShodanInternetDBProvider(BaseProvider):
    """Passive IP intelligence lookup using Shodan InternetDB."""

    name = "shodan_internetdb"
    BASE_URL = "https://internetdb.shodan.io"

    def __init__(
        self,
        client: HttpClient | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.client = client or HttpClient(timeout_seconds)
        self.ttl = timedelta(hours=24)

    def normalize(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Map InternetDB fields into the shared schema."""
        return {
            "ip_address": payload.get("ip"),
            "hostnames": payload.get("hostnames", []),
            "ports": payload.get("ports", []),
            "tags": payload.get("tags", []),
            "cpe_identifiers": payload.get("cpes", []),
            "vulnerability_identifiers": payload.get("vulns", []),
        }

    def lookup(self, ip_address: str) -> ProviderResult:
        retrieved_at = datetime.now(timezone.utc)

        status, payload, error = self.client.get_json(
            f"{self.BASE_URL}/{ip_address}"
        )

        if status == "no_data":
            return ProviderResult(
                provider=self.name,
                status="no_data",
                retrieved_at=retrieved_at,
                error_code=None,
                error_message=None,
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
                error_message="Shodan InternetDB response did not include an IP address.",
            )

        return ProviderResult(
            provider=self.name,
            status="success",
            retrieved_at=retrieved_at,
            expires_at=retrieved_at + self.ttl,
            normalized_data=self.normalize(payload),
            raw_data=payload,
        )
