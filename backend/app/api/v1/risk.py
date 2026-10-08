"""
S.H.A.D.E. — Risk Router
Role: Member 1 — Core Architecture + Backend + Database + Integration

Integration Contract for Member 3 (AI/ML + Risk Scoring).

Member 3 submits risk results; backend persists and exposes them.
Backend does NOT re-implement Member 3's scoring logic.

Endpoints:
  POST /risk/submit        — Member 3 submits a risk result
  GET  /risk/{exposure_id} — Get latest risk result for an exposure
"""

import logging

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.errors import NotFoundError
from backend.app.database.models import Exposure, RiskResult
from backend.app.database.session import get_db
from backend.app.schemas.schemas import RiskResultResponse, RiskResultSubmitRequest

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "/submit",
    summary="Member 3: Submit a risk result for an exposure",
)
async def submit_risk_result(
    body: RiskResultSubmitRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    **Integration Contract for Member 3 (AI/ML + Anomaly Engine)**

    Member 3 calls this endpoint to persist a computed risk result.
    Backend stores it and makes it available via GET /risk/{exposure_id}.

    Risk Classification (from PRODUCT_REQUIREMENTS.md §19):
      - score=0           → risk_level=NONE      (no exposure)
      - risk_level=LOW    → low-risk website
      - risk_level=MEDIUM → private organization
      - risk_level=CRITICAL → public organization

    Backend does NOT override or recompute the score.
    analysis_metadata must NOT contain raw PII.
    """
    exposure = await db.get(Exposure, body.exposure_id)
    if exposure is None:
        raise NotFoundError("Exposure not found.")

    import json

    result = RiskResult(
        exposure_id=body.exposure_id,
        risk_score=body.risk_score,
        risk_level=body.risk_level,
        analysis_metadata=json.dumps(body.analysis_metadata) if body.analysis_metadata else None,
        scored_by="member3-risk-engine",
    )
    db.add(result)
    await db.flush()

    # Update Case risk fields if a Case exists for this exposure
    from backend.app.database.models import Case
    case_result = await db.execute(select(Case).where(Case.exposure_id == body.exposure_id))
    case = case_result.scalar_one_or_none()
    if case:
        case.risk_score = body.risk_score
        case.risk_level = body.risk_level

    logger.info(
        "[Risk] Result stored: exposure_id=%s score=%.1f level=%s",
        body.exposure_id, body.risk_score, body.risk_level,
    )
    return {"risk_result_id": result.id, "status": "stored"}


@router.get("/{exposure_id}", response_model=RiskResultResponse)
async def get_risk_result(exposure_id: str, db: AsyncSession = Depends(get_db)):
    """Return the latest risk result for the given exposure."""
    stmt = (
        select(RiskResult)
        .where(RiskResult.exposure_id == exposure_id)
        .order_by(RiskResult.scored_at.desc())
        .limit(1)
    )
    result = await db.execute(stmt)
    rr = result.scalar_one_or_none()
    if rr is None:
        raise NotFoundError("No risk result found for this exposure.")
    return RiskResultResponse(
        id=rr.id,
        exposure_id=rr.exposure_id,
        risk_score=rr.risk_score,
        risk_level=rr.risk_level,
        scored_at=rr.scored_at,
        analysis_metadata=rr.analysis_metadata,
    )
