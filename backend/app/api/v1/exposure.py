"""
S.H.A.D.E. — Exposure Router
Role: Member 1 — Core Architecture + Backend + Database + Integration

Integration Contract for Member 2 (Security + Threat Engine).

Member 2 calls these endpoints to:
  - Submit a discovered exposure for persistence.
  - Trigger a manual exposure search.

Endpoints:
  POST /exposure/submit        — Member 2 submits a discovered exposure
  POST /exposure/search        — Initiate a manual exposure search
  GET  /exposure/              — List all exposures
  GET  /exposure/{id}          — Get single exposure
"""

import logging
from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.errors import NotFoundError
from backend.app.database.models import Exposure, RiskResult
from backend.app.database.session import get_db
from backend.app.schemas.schemas import (
    ExposureResponse,
    ExposureSearchRequest,
    ExposureSubmitRequest,
)

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "/submit",
    summary="Member 2: Submit a discovered exposure for persistence",
)
async def submit_exposure(
    body: ExposureSubmitRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    **Integration Contract for Member 2 (Security Engine)**

    Member 2 calls this endpoint to persist a discovered exposure/breach record.
    Backend stores it; Member 2 owns the discovery and detection logic.

    Fields:
    - sensitive_value_id : (optional) vault record associated with the exposure.
    - data_type          : Type of data exposed (EMAIL, PASSWORD, etc.).
    - organization       : Organization/platform where the breach occurred.
    - source_url         : Source of discovery (URL, database name).
    - evidence_summary   : Safe, sanitized description of evidence (no raw PII).
    - discovery_mode     : MANUAL (user-initiated) | AUTOMATIC (background monitor).
    """
    exposure = Exposure(
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
        "[Exposure] New exposure id=%s type=%s org=%s mode=%s",
        exposure.id, body.data_type, body.organization, body.discovery_mode,
    )
    return {"exposure_id": exposure.id, "status": "stored"}


@router.post("/search", summary="Initiate manual exposure search")
async def search_exposure(body: ExposureSearchRequest):
    """
    **Integration Contract for Member 2**

    Initiates a manual exposure search. The search_value_hash (SHA-256) is passed
    to Member 2's security engine. Member 2 performs the actual breach lookup
    (HIBP k-anonymity, OSINT, etc.) and calls POST /exposure/submit with results.

    Raw sensitive values must NOT be sent here — only SHA-256 hashes.
    """
    # Backend orchestration point: in full integration, this would:
    # 1. Dispatch search request to Member 2's security engine via internal queue.
    # 2. Member 2 performs HIBP/OSINT lookup.
    # 3. Member 2 calls /exposure/submit with findings.
    # For MVP: return a contract acknowledgment.
    return {
        "search_type": body.search_type,
        "status": "SEARCH_DISPATCHED",
        "message": (
            "Search dispatched to security engine. "
            "Member 2 will call POST /exposure/submit with results."
        ),
    }


@router.get("/", summary="List all stored exposures")
async def list_exposures(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Exposure))
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
async def get_exposure(exposure_id: str, db: AsyncSession = Depends(get_db)):
    exposure = await db.get(Exposure, exposure_id)
    if exposure is None:
        raise NotFoundError("Exposure not found.")
    return ExposureResponse(
        id=exposure.id,
        data_type=exposure.data_type,
        organization=exposure.organization,
        source_url=exposure.source_url,
        evidence_summary=exposure.evidence_summary,
        discovered_at=exposure.discovered_at,
        discovery_mode=exposure.discovery_mode,
    )
