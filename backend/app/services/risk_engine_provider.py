"""
S.H.A.D.E. — Risk Engine Provider Interface
Role: Member 1 — Core Architecture + Backend + Database + Integration

Integration Contract for Member 3 (AI/ML Risk Scoring).
Backend does NOT recompute or duplicate the AI risk algorithm.
Backend stores and consumes results.

Risk Categories (from PRODUCT_REQUIREMENTS.md §19):
  - 0            → NONE (no exposure)
  - LOW          → low-risk website
  - MEDIUM       → private organization
  - CRITICAL     → public organization
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class RiskScoreResult:
    risk_score: float
    risk_level: str
    analysis_metadata: Optional[Dict[str, Any]] = None


class RiskEngineProvider(ABC):
    """Abstract interface for risk scoring engines."""

    @abstractmethod
    async def evaluate_risk(
        self,
        exposure_id: str,
        data_type: str,
        organization: Optional[str] = None,
    ) -> Optional[RiskScoreResult]:
        """
        Evaluate risk score (0-100) and risk level for a discovered exposure.
        Returns None if engine is unavailable.
        """

    @abstractmethod
    def is_available(self) -> bool:
        """Check if Member 3's AI/ML risk engine is active/connected."""


class DevRiskEngineProvider(RiskEngineProvider):
    """
    Development/test risk provider stub.
    Provides simple deterministic category mapping without duplicating AI logic.
    """

    def is_available(self) -> bool:
        return True

    async def evaluate_risk(
        self,
        exposure_id: str,
        data_type: str,
        organization: Optional[str] = None,
    ) -> Optional[RiskScoreResult]:
        # Return deterministic category baseline
        org_lower = (organization or "").lower()
        if "gov" in org_lower or "public" in org_lower:
            return RiskScoreResult(
                risk_score=95.0,
                risk_level="CRITICAL",
                analysis_metadata={"source": "dev_risk_engine", "classification": "public_org"},
            )
        elif "corp" in org_lower or "private" in org_lower:
            return RiskScoreResult(
                risk_score=60.0,
                risk_level="MEDIUM",
                analysis_metadata={"source": "dev_risk_engine", "classification": "private_org"},
            )
        return RiskScoreResult(
            risk_score=25.0,
            risk_level="LOW",
            analysis_metadata={"source": "dev_risk_engine", "classification": "low_risk"},
        )


class Member3RiskEngineStub(RiskEngineProvider):
    """Production interface stub for Member 3's AI risk engine."""

    def is_available(self) -> bool:
        return False

    async def evaluate_risk(
        self,
        exposure_id: str,
        data_type: str,
        organization: Optional[str] = None,
    ) -> Optional[RiskScoreResult]:
        logger.info("[RiskEngine] Member 3 production AI engine not yet connected.")
        return None


_risk_engine_instance: Optional[RiskEngineProvider] = None


def set_risk_engine_provider(provider: RiskEngineProvider) -> None:
    """Set or override the active risk engine provider."""
    global _risk_engine_instance
    _risk_engine_instance = provider


def get_risk_engine_provider() -> RiskEngineProvider:
    global _risk_engine_instance
    if _risk_engine_instance is None:
        try:
            from ai.risk_engine.engine import AIRiskEngine
            _risk_engine_instance = AIRiskEngine()
        except ImportError:
            _risk_engine_instance = DevRiskEngineProvider()
    return _risk_engine_instance
