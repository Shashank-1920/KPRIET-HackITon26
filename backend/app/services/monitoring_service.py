"""
S.H.A.D.E. — Exposure Monitoring Scheduler & Orchestration Service
Role: Member 1 — Core Architecture + Backend + Database + Integration

Orchestrates automatic exposure monitoring for owner-vaulted sensitive values:
- Runs in background or on-demand.
- Respects offline mode without failing the local vault.
- Normalizes external findings via ExposureProvider.
- Emits results to RiskEngineProvider.
- Persists owner-isolated exposure and case records.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database.models import Case, Exposure, RiskResult, SensitiveValue
from backend.app.services.exposure_provider import get_exposure_provider
from backend.app.services.risk_engine_provider import get_risk_engine_provider

logger = logging.getLogger(__name__)


class MonitoringService:
    """Service orchestrating background exposure checks for vaulted values."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db
        self._exposure_provider = get_exposure_provider()
        self._risk_engine = get_risk_engine_provider()

    async def run_monitoring_cycle(self, owner_id: str) -> Dict[str, Any]:
        """
        Execute an exposure monitoring pass for the given owner.
        Gracefully handles offline mode.
        """
        # 1. Check provider availability (offline handling)
        if self._exposure_provider is None or not self._exposure_provider.is_available():
            logger.info("[MonitoringService] External provider offline or unavailable. Vault remains unaffected.")
            return {
                "owner_id": owner_id,
                "status": "OFFLINE_PENDING",
                "message": "Exposure provider is offline or unconfigured. Monitoring marked pending.",
                "new_exposures": 0,
            }

        # 2. Retrieve owner's active sensitive values
        stmt = select(SensitiveValue).where(
            SensitiveValue.owner_id == owner_id,
            SensitiveValue.deleted_at.is_(None),
        )
        res = await self._db.execute(stmt)
        values = res.scalars().all()

        new_exposures_count = 0

        # 3. Query provider using lookup hashes
        for sv in values:
            try:
                findings = await self._exposure_provider.search(
                    search_type=sv.data_type,
                    query_hash=sv.lookup_hash,
                )

                for finding in findings:
                    # Check if exposure already recorded
                    exp_check = await self._db.execute(
                        select(Exposure).where(
                            Exposure.owner_id == owner_id,
                            Exposure.sensitive_value_id == sv.id,
                            Exposure.organization == finding.organization,
                        )
                    )
                    existing_exp = exp_check.scalar_one_or_none()
                    if existing_exp is not None:
                        continue  # Already recorded

                    # Persist new exposure
                    new_exp = Exposure(
                        owner_id=owner_id,
                        sensitive_value_id=sv.id,
                        data_type=finding.data_type,
                        organization=finding.organization,
                        source_url=finding.source,
                        evidence_summary=finding.evidence_summary,
                        discovery_mode="AUTOMATIC",
                        discovered_at=finding.discovered_at,
                    )
                    self._db.add(new_exp)
                    await self._db.flush()
                    new_exposures_count += 1

                    # 4. Invoke Risk Engine contract
                    risk_score_val = None
                    risk_level_val = None
                    if self._risk_engine and self._risk_engine.is_available():
                        risk_res = await self._risk_engine.evaluate_risk(
                            exposure_id=new_exp.id,
                            data_type=finding.data_type,
                            organization=finding.organization,
                        )
                        if risk_res:
                            risk_score_val = risk_res.risk_score
                            risk_level_val = risk_res.risk_level
                            rr = RiskResult(
                                exposure_id=new_exp.id,
                                risk_score=risk_res.risk_score,
                                risk_level=risk_res.risk_level,
                                scored_by="member3-risk-engine",
                            )
                            self._db.add(rr)

                    # 5. Create investigation Case
                    case = Case(
                        owner_id=owner_id,
                        exposure_id=new_exp.id,
                        organization=finding.organization,
                        data_type=finding.data_type,
                        affected_data_description=f"Automated exposure monitoring discovery for {finding.data_type}",
                        discovery_date=finding.discovered_at,
                        evidence=finding.evidence_summary,
                        risk_score=risk_score_val,
                        risk_level=risk_level_val,
                        status="OPEN",
                    )
                    self._db.add(case)
                    await self._db.flush()

            except Exception as exc:
                logger.error("[MonitoringService] Error monitoring value %s: %s", sv.id, exc)

        return {
            "owner_id": owner_id,
            "status": "COMPLETED",
            "values_monitored": len(values),
            "new_exposures": new_exposures_count,
        }
