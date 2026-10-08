"""
S.H.A.D.E. — Exposure Router
Role: Member 1 — Core Architecture + Backend + Database + Integration

Integration Contract for Member 2 (Security + Threat Engine).

Endpoints:
  POST /exposure/submit        — Member 2 submits a discovered exposure
  POST /exposure/search        — Initiate exposure search via ExposureProvider
  POST /exposure/monitor/run   — Trigger exposure monitoring cycle
  GET  /exposure/              — List owner-scoped exposures
  GET  /exposure/{id}          — Get single exposure

INVARIANTS:
  - All routes require authenticated session.
  - All exposures are strictly isolated to the authenticated owner.
  - Results are never fabricated. If provider is unavailable, clear status is returned.
"""

import logging
from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.dependencies import SessionContext, get_current_session
from backend.app.core.errors import NotFoundError
from backend.app.database.models import Exposure, RiskResult
from backend.app.database.session import get_db
from backend.app.schemas.schemas import (
    ExposureResponse,
    ExposureSearchRequest,
    ExposureSubmitRequest,
)
from backend.app.services.exposure_provider import get_exposure_provider
from backend.app.services.monitoring_service import MonitoringService
from backend.app.services.risk_engine_provider import get_risk_engine_provider

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "/submit",
    summary="Member 2: Submit a discovered exposure for persistence",
)
async def submit_exposure(
    body: ExposureSubmitRequest,
    session_ctx: SessionContext = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    """
    Persist a discovered exposure scoped to the authenticated owner.
    """
    exposure = Exposure(
        owner_id=session_ctx.owner.id,
        sensitive_value_id=body.sensitive_value_id,
        data_type=body.data_type,
        organization=body.organization,
        source_url=body.source_url,
        evidence_summary=body.evidence_summary,
        discovery_mode=body.discovery_mode,
    )
    db.add(exposure)
    await db.flush()
    logger.info(
        "[Exposure] New exposure id=%s type=%s org=%s owner=%s",
        exposure.id, body.data_type, body.organization, session_ctx.owner.id,
    )
    return {"exposure_id": exposure.id, "status": "stored"}


@router.post("/search", summary="Initiate exposure search via configured provider")
async def search_exposure(
    body: ExposureSearchRequest,
    session_ctx: SessionContext = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    """
    Initiate an exposure search using the configured ExposureProvider.
    Normalizes findings and persists exposure records scoped to the owner.
    """
    provider = get_exposure_provider()
    if provider is None or not provider.is_available():
        return {
            "search_type": body.search_type,
            "status": "PROVIDER_UNAVAILABLE",
            "message": "Exposure search provider is currently unavailable or unconfigured.",
            "results": [],
        }

    findings = await provider.search(body.search_type, body.search_value_hash)
    stored_exposures = []
    risk_engine = get_risk_engine_provider()

    for item in findings:
        exp = Exposure(
            owner_id=session_ctx.owner.id,
            sensitive_value_id=body.sensitive_value_id,
            data_type=item.data_type,
            organization=item.organization,
            source_url=item.source,
            evidence_summary=item.evidence_summary,
            discovery_mode="MANUAL",
            discovered_at=item.discovered_at,
        )
        db.add(exp)
        await db.flush()
        stored_exposures.append(exp.id)

        if risk_engine and risk_engine.is_available():
            risk_res = await risk_engine.evaluate_risk(
                exposure_id=exp.id,
                data_type=item.data_type,
                organization=item.organization,
            )
            if risk_res:
                rr = RiskResult(
                    exposure_id=exp.id,
                    risk_score=risk_res.risk_score,
                    risk_level=risk_res.risk_level,
                    scored_by="member3-risk-engine",
                )
                db.add(rr)

    return {
        "search_type": body.search_type,
        "status": "COMPLETED",
        "count": len(stored_exposures),
        "exposure_ids": stored_exposures,
    }


@router.post("/monitor/run", summary="Trigger exposure monitoring cycle")
async def run_monitoring_cycle(
    session_ctx: SessionContext = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    """Trigger background monitoring cycle for the authenticated owner."""
    svc = MonitoringService(db)
    result = await svc.run_monitoring_cycle(session_ctx.owner.id)
    return result


@router.get("/", summary="List all stored exposures for authenticated owner")
async def list_exposures(
    session_ctx: SessionContext = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Exposure).where(Exposure.owner_id == session_ctx.owner.id)
    )
    exposures = result.scalars().all()
    items = []
    for e in exposures:
        items.append(
            ExposureResponse(
                id=e.id,
                data_type=e.data_type,
                organization=e.organization,
                source_url=e.source_url,
                evidence_summary=e.evidence_summary,
                discovered_at=e.discovered_at,
                discovery_mode=e.discovery_mode,
            )
        )
    return {"count": len(items), "exposures": items}


@router.get("/{exposure_id}", response_model=ExposureResponse)
async def get_exposure(
    exposure_id: str,
    session_ctx: SessionContext = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    exp = await db.get(Exposure, exposure_id)
    if exp is None or exp.owner_id != session_ctx.owner.id:
        raise NotFoundError("Exposure not found.")
    return ExposureResponse(
        id=exp.id,
        data_type=exp.data_type,
        organization=exp.organization,
        source_url=exp.source_url,
        evidence_summary=exp.evidence_summary,
        discovered_at=exp.discovered_at,
        discovery_mode=exp.discovery_mode,
    )
