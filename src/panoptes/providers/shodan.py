from __future__ import annotations

import os
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


class ShodanHostProvider(BaseProvider):
    """Passive IP intelligence lookup using the authenticated Shodan Host API.

    Observations are historical, provider-reported data, not proof of a live
    service or a currently exploitable vulnerability.
    """

    name = "shodan_host"
    BASE_URL = "https://api.shodan.io/shodan/host"

    def __init__(
        self,
        api_key: str | None = None,
        client: HttpClient | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.api_key = (
            api_key if api_key is not None else os.getenv("SHODAN_API_KEY")
        )
        self.client = client or HttpClient(timeout_seconds)
        self.ttl = timedelta(hours=24)

    @staticmethod
    def _as_list(value: Any) -> list[Any]:
        """Return value if it is a list, otherwise an empty list."""
        return value if isinstance(value, list) else []

    def _normalize_service(self, banner: dict[str, Any]) -> dict[str, Any]:
        """Reduce one Shodan banner to a concise service observation."""
        shodan_meta = banner.get("_shodan")
        module = shodan_meta.get("module") if isinstance(shodan_meta, dict) else None

        return {
            "port": banner.get("port"),
            "transport": banner.get("transport"),
            "product": banner.get("product"),
            "version": banner.get("version"),
            "module": module,
            "observed_at": banner.get("timestamp"),
        }

    def normalize(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Map Shodan Host fields into the shared schema."""
        banners = [
            banner
            for banner in self._as_list(payload.get("data"))
            if isinstance(banner, dict)
        ]
        services = [self._normalize_service(banner) for banner in banners]

        ports = self._as_list(payload.get("ports"))
        if not ports:
            ports = [s["port"] for s in services if s["port"] is not None]

        vulns = payload.get("vulns")
        if isinstance(vulns, dict):
            vulns = list(vulns)

        return {
            "ip_address": payload.get("ip_str"),
            "asn": payload.get("asn"),
            "organization": payload.get("org"),
            "isp": payload.get("isp"),
            "country_code": payload.get("country_code"),
            "country_name": payload.get("country_name"),
            "city": payload.get("city"),
            "hostnames": self._as_list(payload.get("hostnames")),
            "domains": self._as_list(payload.get("domains")),
            "ports": sorted(set(ports)),
            "tags": self._as_list(payload.get("tags")),
            "vulnerability_identifiers": self._as_list(vulns),
            "services": services,
            "last_update": payload.get("last_update"),
        }

    def lookup(self, ip_address: str) -> ProviderResult:
        retrieved_at = datetime.now(timezone.utc)

        if not self.api_key:
            return ProviderResult(
                provider=self.name,
                status="auth_error",
                retrieved_at=retrieved_at,
                error_code="missing_api_key",
                error_message="Shodan API key is not configured.",
            )

        status, payload, error = self.client.get_json(
            f"{self.BASE_URL}/{ip_address}",
            params={"key": self.api_key},
        )

        if status == "no_data":
            return ProviderResult(
                provider=self.name,
                status="no_data",
                retrieved_at=retrieved_at,
            )

        if status != "success":
            return ProviderResult(
                provider=self.name,
                status=status,
                retrieved_at=retrieved_at,
                error_code=status,
                error_message=error,
            )

        if not payload.get("ip_str"):
            return ProviderResult(
                provider=self.name,
                status="error",
                retrieved_at=retrieved_at,
                error_code="unexpected_payload",
                error_message="Shodan Host response did not include an IP address.",
            )

        try:
            normalized = self.normalize(payload)
        except (TypeError, AttributeError):
            return ProviderResult(
                provider=self.name,
                status="error",
                retrieved_at=retrieved_at,
                error_code="unexpected_payload",
                error_message="Shodan Host response had an unexpected structure.",
            )

        return ProviderResult(
            provider=self.name,
            status="success",
            retrieved_at=retrieved_at,
            expires_at=retrieved_at + self.ttl,
            normalized_data=normalized,
            raw_data=payload,
        )
