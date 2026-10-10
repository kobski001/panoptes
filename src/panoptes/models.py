
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal


ProviderName = Literal[
    "shodan_host",
    "shodan_internetdb",
    "virustotal",
    "ipinfo_lite",
]

ProviderStatus = Literal[
    "success",
    "no_data",
    "rate_limited",
    "auth_error",
    "permission_error",
    "timeout",
    "error",
]

OverallStatus = Literal["success", "partial", "failed"]


@dataclass(slots=True)
class ProviderResult:
    """One provider's result for a single IP lookup."""

    provider: ProviderName
    status: ProviderStatus
    retrieved_at: datetime

    normalized_data: dict[str, Any] = field(default_factory=dict)
    raw_data: dict[str, Any] = field(default_factory=dict)

    cached: bool = False
    expires_at: datetime | None = None

    error_code: str | None = None
    error_message: str | None = None

    @property
    def is_usable(self) -> bool:
        """Whether this result contains a completed, usable response."""
        return self.status in {"success", "no_data"}


@dataclass(slots=True)
class ScanResult:
    """Combined results from all providers for one IP lookup."""

    scan_id: str
    ip_address: str
    started_at: datetime
    completed_at: datetime | None = None
    overall_status: OverallStatus = "failed"
    provider_results: list[ProviderResult] = field(default_factory=list)

    def calculate_status(self) -> OverallStatus:
        """Determine whether the scan succeeded, partially succeeded, or failed."""
        if not self.provider_results:
            return "failed"

        usable_count = sum(
            result.is_usable for result in self.provider_results
        )

        if usable_count == len(self.provider_results):
            return "success"

        if usable_count > 0:
            return "partial"

        return "failed"
