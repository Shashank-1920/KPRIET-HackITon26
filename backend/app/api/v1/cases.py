"""
S.H.A.D.E. — Case Management Router
Role: Member 1 — Core Architecture + Backend + Database + Integration

Endpoints:
  POST /cases/              — Create investigation case
  GET  /cases/              — List all cases
  GET  /cases/{id}          — Get single case
  PATCH /cases/{id}         — Update case status/risk
"""

import logging

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.errors import NotFoundError
from backend.app.database.models import Case, Exposure
from backend.app.database.session import get_db
from backend.app.schemas.schemas import (
    CaseCreateRequest,
    CaseResponse,
    CaseUpdateRequest,
)

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/", response_model=CaseResponse, summary="Create investigation case")
async def create_case(body: CaseCreateRequest, db: AsyncSession = Depends(get_db)):
    """
    Create a new investigation case for an exposure.
    evidence and unsupported_notes are clearly separated — the backend
    will NEVER conflate confirmed evidence with assumptions.
    """
    exposure = await db.get(Exposure, body.exposure_id)
    if exposure is None:
        raise NotFoundError("Exposure not found.")

    case = Case(
        exposure_id=body.exposure_id,
        organization=body.organization,
        data_type=body.data_type,
        affected_data_description=body.affected_data_description,
        discovery_date=body.discovery_date,
        evidence=body.evidence,
        unsupported_notes=body.unsupported_notes,
        status="OPEN",
    )
    db.add(case)
    await db.flush()
    return _to_response(case)


@router.get("/", summary="List all investigation cases")
async def list_cases(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Case))
    cases = result.scalars().all()
    return {"count": len(cases), "cases": [_to_response(c) for c in cases]}


@router.get("/{case_id}", response_model=CaseResponse)
async def get_case(case_id: str, db: AsyncSession = Depends(get_db)):
    case = await db.get(Case, case_id)
    if case is None:
        raise NotFoundError("Case not found.")
    return _to_response(case)


@router.patch("/{case_id}", response_model=CaseResponse, summary="Update case status/risk")
async def update_case(
    case_id: str, body: CaseUpdateRequest, db: AsyncSession = Depends(get_db)
):
    case = await db.get(Case, case_id)
    if case is None:
        raise NotFoundError("Case not found.")
    if body.status:
        case.status = body.status
    if body.evidence:
        case.evidence = body.evidence
    if body.risk_score is not None:
        case.risk_score = body.risk_score
    if body.risk_level:
        case.risk_level = body.risk_level
    await db.flush()
    return _to_response(case)


def _to_response(case: Case) -> CaseResponse:
    return CaseResponse(
        id=case.id,
        exposure_id=case.exposure_id,
        organization=case.organization,
        data_type=case.data_type,
        affected_data_description=case.affected_data_description,
        discovery_date=case.discovery_date,
        evidence=case.evidence,
        unsupported_notes=case.unsupported_notes,
        risk_score=case.risk_score,
        risk_level=case.risk_level,
        status=case.status,
        created_at=case.created_at,
        updated_at=case.updated_at,
    )
