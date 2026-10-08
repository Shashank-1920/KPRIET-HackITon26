"""
S.H.A.D.E. — AI/ML Risk Engine Implementation
Role: Member 3 — AI/ML + Detection + Anomaly Analysis

Implements the RiskEngineProvider contract defined by Member 1.
Computes explainable 0–100 numeric risk scores and categorizes into locked product levels:
- NO EXPOSURE  → 0
- LOW          → Low-risk website
- MEDIUM       → Private organization (e.g. college, banking portal)
- CRITICAL     → Public organization (government, national archive, public registry)

INVARIANTS:
- Does NOT duplicate logic in backend; backend calls this engine.
- Provides explainable reasoning and feature metadata.
"""

import logging
from typing import Any, Dict, Optional

from backend.app.services.risk_engine_provider import RiskEngineProvider, RiskScoreResult

logger = logging.getLogger(__name__)


class AIRiskEngine(RiskEngineProvider):
    """
    Member 3's AI Risk Scoring Engine.
    Evaluates exposure severity based on organization entity classification,
    data type sensitivity weight, and evidence credibility.
    """

    def __init__(self, is_online: bool = True):
        self._is_online = is_online

    def is_available(self) -> bool:
        return self._is_online

    def set_availability(self, available: bool) -> None:
        self._is_online = available

    async def evaluate_risk(
        self,
        exposure_id: str,
        data_type: str,
        organization: Optional[str] = None,
    ) -> Optional[RiskScoreResult]:
        """
        Evaluate risk score (0-100) and risk level for an exposure record.
        Returns None if engine is offline/unavailable.
        """
        if not self.is_available():
            logger.info("[AIRiskEngine] Risk engine is offline/unavailable.")
            return None

        org_name = (organization or "").lower()
        d_type = (data_type or "").upper()

        # 1. Base Score & Category classification (Locked Product Semantics §19)
        # Public organization -> CRITICAL
        # Private organization (college, bank, enterprise) -> MEDIUM
        # Low-risk website -> LOW
        if not org_name:
            base_score = 15.0
            risk_level = "LOW"
            category_reason = "Unspecified low-risk online source"
        elif any(k in org_name for k in ["forum", "blog", "community", "board", "discussion"]):
            base_score = 25.0
            risk_level = "LOW"
            category_reason = "Low-risk public website or discussion board"
        elif any(k in org_name for k in ["college", "university", "bank", "corp", "private", "fin", "health"]):
            base_score = 55.0
            risk_level = "MEDIUM"
            category_reason = "Private organization (financial, educational, or corporate portal)"
        elif any(k in org_name for k in ["public", "gov", "national", "archive", "ministry"]):
            base_score = 90.0
            risk_level = "CRITICAL"
            category_reason = "Public organization / government / national repository exposure"
        else:
            base_score = 25.0
            risk_level = "LOW"
            category_reason = "Low-risk public website or discussion board"

        # 2. Data Type Sensitivity Multiplier / Bonus
        # Aadhaar, Credentials, Credit Cards amplify risk
        type_weight = {
            "AADHAAR": 10.0,
            "CREDIT_CARD": 10.0,
            "PASSWORD": 9.0,
            "API_KEY": 8.0,
            "PAN": 7.0,
            "URL_WITH_SECRET": 6.0,
            "UPI_ID": 5.0,
            "MOBILE": 4.0,
            "VEHICLE_PLATE": 3.0,
            "EMAIL": 2.0,
        }.get(d_type, 1.0)

        raw_score = base_score + (type_weight * 0.8)
        # Clamp score to 0 - 100
        final_score = min(100.0, max(0.0, round(raw_score, 1)))

        # Ensure locked level invariants:
        if base_score >= 90.0:
            final_level = "CRITICAL"
        elif base_score >= 55.0:
            final_level = "MEDIUM"
        else:
            final_level = "LOW"

        metadata: Dict[str, Any] = {
            "engine": "AIRiskEngine-v2",
            "category_reason": category_reason,
            "data_type_weight": type_weight,
            "confidence": 0.94,
            "model_version": "hybrid-heuristic-v3",
        }

        logger.info(
            "[AIRiskEngine] Evaluated exposure %s: score=%.1f level=%s reason=%s",
            exposure_id,
            final_score,
            final_level,
            category_reason,
        )

        return RiskScoreResult(
            risk_score=final_score,
            risk_level=final_level,
            analysis_metadata=metadata,
        )
