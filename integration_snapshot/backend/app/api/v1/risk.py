"""
S.H.A.D.E. — Risk Router
Role: Member 1 — Core Architecture + Backend + Database + Integration

Integration Contract for Member 3 (AI/ML + Risk Scoring).

Endpoints:
  POST /risk/submit        — Member 3 submits a risk result
  GET  /risk/{exposure_id} — Get latest risk result for an exposure

INVARIANTS:
  - All routes require authenticated session.
  - Scoped to authenticated owner.
  - Backend does not recompute or override Member 3's risk score.
"""

import json
import logging

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.dependencies import SessionContext, get_current_session
from backend.app.core.errors import NotFoundError
from backend.app.database.models import Case, Exposure, RiskResult
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
    session_ctx: SessionContext = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    """
    Persist a computed risk result for an owner's exposure.
    Backend does not override or recalculate the score.
    """
    exposure = await db.get(Exposure, body.exposure_id)
    if exposure is None or exposure.owner_id != session_ctx.owner.id:
        raise NotFoundError("Exposure not found.")

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
    case_result = await db.execute(
        select(Case).where(Case.exposure_id == body.exposure_id, Case.owner_id == session_ctx.owner.id)
    )
    case = case_result.scalar_one_or_none()
    if case:
        case.risk_score = body.risk_score
        case.risk_level = body.risk_level

    logger.info(
        "[Risk] Result stored: exposure_id=%s score=%.1f level=%s owner=%s",
        body.exposure_id, body.risk_score, body.risk_level, session_ctx.owner.id,
    )
    return {"risk_result_id": result.id, "status": "stored"}


@router.get("/{exposure_id}", response_model=RiskResultResponse)
async def get_risk_result(
    exposure_id: str,
    session_ctx: SessionContext = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    """Return the latest risk result for the given exposure belonging to owner."""
    exposure = await db.get(Exposure, exposure_id)
    if exposure is None or exposure.owner_id != session_ctx.owner.id:
        raise NotFoundError("Exposure not found.")

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
