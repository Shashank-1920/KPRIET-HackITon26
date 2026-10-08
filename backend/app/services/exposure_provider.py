"""
S.H.A.D.E. — Exposure Provider Abstraction & Result Normalization
Role: Member 1 — Core Architecture + Backend + Database + Integration

Integration Contract for Member 2 (Breach Intelligence / Security Engine).
Backend provides the orchestration contract; Member 2 implements detection internals.

INVARIANTS:
- Backend normalizes and persists breach/exposure records.
- If no external provider is configured, backend returns clear provider unavailable status.
- Real API keys are never hardcoded.
- Results are never fabricated.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.app.core.config import settings

logger = logging = __import__("logging").getLogger(__name__)


@dataclass
class NormalizedExposure:
    """Normalized exposure record across all external breach intelligence sources."""
    source: str
    organization: str
    data_type: str
    evidence_summary: str
    discovered_at: datetime
    attribution_info: Optional[str] = None
    provider_ref: Optional[str] = None
    confidence: float = 1.0
    status: str = "VERIFIED"


class ExposureProvider(ABC):
    """Abstract interface for breach intelligence search and monitoring."""

    @abstractmethod
    async def search(self, search_type: str, query_hash: str) -> List[NormalizedExposure]:
        """
        Execute an exposure lookup using a privacy-preserving query hash.
        Raw sensitive values must NEVER be transmitted.
        """

    @abstractmethod
    def is_available(self) -> bool:
        """Check if provider is configured and available (online)."""


class MockExposureProvider(ExposureProvider):
    """
    Development/test exposure provider.
    Returns deterministic test findings when invoked with specific test query hashes.
    """

    def is_available(self) -> bool:
        return True

    async def search(self, search_type: str, query_hash: str) -> List[NormalizedExposure]:
        # Return empty list by default unless test query hash matches
        if query_hash.startswith("test_breached_"):
            return [
                NormalizedExposure(
                    source="https://breach-database.test/records",
                    organization="MockTestCorp",
                    data_type=search_type,
                    evidence_summary="Discovered in test synthetic breach dump.",
                    discovered_at=datetime.now(timezone.utc),
                    attribution_info="Synthetic test intelligence source",
                    provider_ref="mock-exp-001",
                    confidence=0.95,
                    status="VERIFIED",
                )
            ]
        return []


class HIBPExposureProviderStub(ExposureProvider):
    """
    Production breach intelligence provider stub (HIBP k-anonymity).
    Requires HIBP_API_KEY environment variable.
    """

    def is_available(self) -> bool:
        return bool(settings.hibp_api_key)

    async def search(self, search_type: str, query_hash: str) -> List[NormalizedExposure]:
        if not self.is_available():
            logger.info("[ExposureProvider] HIBP provider unavailable or unconfigured.")
            return []
        # Member 2 will connect their breach intelligence engine here
        return []


_exposure_provider_instance: Optional[ExposureProvider] = None


def get_exposure_provider() -> Optional[ExposureProvider]:
    global _exposure_provider_instance
    if _exposure_provider_instance is None:
        if settings.shade_env == "production":
            _exposure_provider_instance = HIBPExposureProviderStub()
        else:
            _exposure_provider_instance = MockExposureProvider()
    return _exposure_provider_instance
