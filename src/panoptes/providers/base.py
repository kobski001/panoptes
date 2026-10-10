
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from panoptes.models import ProviderName, ProviderResult


class BaseProvider(ABC):
    """Common interface for passive IP intelligence providers."""

    name: ProviderName

    @abstractmethod
    def lookup(self, ip_address: str) -> ProviderResult:
        """Retrieve intelligence for an IP address."""
        raise NotImplementedError

    @abstractmethod
    def normalize(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Convert provider-specific data into the shared schema."""
        raise NotImplementedError
