"""
S.H.A.D.E. — Erasure Request Router
Role: Member 1 — Core Architecture + Backend + Database + Integration

Statutory data erasure workflow (DPDP Act 2023, Section 12).

INVARIANT: Backend must NOT mark data as deleted without evidence.
User controls when to send the request. 7-day deadline tracked.

Endpoints:
  POST /erasure/               — Create erasure request (DRAFT)
  GET  /erasure/{id}           — Get erasure request
  POST /erasure/{id}/send      — Mark as sent, start 7-day deadline
  POST /erasure/{id}/response  — Record organization response
  POST /erasure/{id}/followup  — Create follow-up request
  GET  /erasure/{id}/deadline  — Check deadline status
"""

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.errors import NotFoundError
from backend.app.database.models import ErasureRequest, FollowUpRequest
from backend.app.database.session import get_db
from backend.app.schemas.schemas import (
    ErasureRequestCreate,
    ErasureRequestResponse,
    ErasureRequestSendResponse,
    ErasureResponseUpdate,
    FollowUpRequestCreate,
    FollowUpResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter()

_DEADLINE_DAYS = 7


@router.post("/", response_model=ErasureRequestResponse, summary="Create erasure request (DRAFT)")
async def create_erasure_request(
    body: ErasureRequestCreate, db: AsyncSession = Depends(get_db)
):
    """
    Create a DRAFT erasure request. User reviews before sending.
    The backend does NOT automatically send the request.
    """
    req = ErasureRequest(
        case_id=body.case_id,
        dpo_email=body.dpo_email,
        legal_basis=body.legal_basis or "DPDP Act 2023, Section 12(1) and Section 12(2)",
        request_body=body.request_body,
        status="DRAFT",
    )
    db.add(req)
    await db.flush()
    return _to_response(req)


@router.get("/{erasure_id}", response_model=ErasureRequestResponse)
async def get_erasure_request(erasure_id: str, db: AsyncSession = Depends(get_db)):
    req = await db.get(ErasureRequest, erasure_id)
    if req is None:
        raise NotFoundError("Erasure request not found.")
    return _to_response(req)


@router.post(
    "/{erasure_id}/send",
    response_model=ErasureRequestSendResponse,
    summary="User sends the erasure request — starts 7-day deadline",
)
async def send_erasure_request(erasure_id: str, db: AsyncSession = Depends(get_db)):
    """
    User confirms they have sent the erasure request.
    Backend records the send date and computes the 7-day statutory deadline.
    Status transitions from DRAFT → SENT.
    """
    req = await db.get(ErasureRequest, erasure_id)
    if req is None:
        raise NotFoundError("Erasure request not found.")
    now = datetime.now(timezone.utc)
    req.request_date = now
    req.deadline_date = now + timedelta(days=_DEADLINE_DAYS)
    req.status = "SENT"
    await db.flush()
    logger.info(
        "[Erasure] Request sent id=%s deadline=%s", erasure_id, req.deadline_date
    )
    return ErasureRequestSendResponse(
        id=req.id,
        status=req.status,
        request_date=req.request_date,
        deadline_date=req.deadline_date,
        message=f"Erasure request marked as sent. 7-day statutory deadline: {req.deadline_date.date()}",
    )


@router.post("/{erasure_id}/response", summary="Record organization response")
async def record_organization_response(
    erasure_id: str, body: ErasureResponseUpdate, db: AsyncSession = Depends(get_db)
):
    """
    Record the organization's response to the erasure request.

    INVARIANT: The backend does NOT mark data as deleted unless `new_status=RESOLVED`
    is explicitly set and evidence of deletion is provided in `organization_response`.
    """
    req = await db.get(ErasureRequest, erasure_id)
    if req is None:
        raise NotFoundError("Erasure request not found.")
    req.organization_response = body.organization_response
    req.status = body.new_status
    await db.flush()
    return {"id": req.id, "status": req.status, "message": "Organization response recorded."}


@router.post("/{erasure_id}/followup", response_model=FollowUpResponse)
async def create_follow_up(
    erasure_id: str, body: FollowUpRequestCreate, db: AsyncSession = Depends(get_db)
):
    """Create a follow-up request if no response received by the 7-day deadline."""
    req = await db.get(ErasureRequest, erasure_id)
    if req is None:
        raise NotFoundError("Erasure request not found.")

    followup = FollowUpRequest(
        erasure_request_id=erasure_id,
        follow_up_body=body.follow_up_body,
        status="DRAFT",
    )
    db.add(followup)
    await db.flush()

    req.status = "FOLLOW_UP_SENT"
    return FollowUpResponse(
        id=followup.id,
        erasure_request_id=followup.erasure_request_id,
        follow_up_body=followup.follow_up_body,
        status=followup.status,
        sent_at=followup.sent_at,
        created_at=followup.created_at,
    )


@router.get("/{erasure_id}/deadline", summary="Check 7-day deadline status")
async def check_deadline(erasure_id: str, db: AsyncSession = Depends(get_db)):
    req = await db.get(ErasureRequest, erasure_id)
    if req is None:
        raise NotFoundError("Erasure request not found.")
    if req.deadline_date is None:
        return {"status": req.status, "deadline_active": False, "message": "Request not yet sent."}
    now = datetime.now(timezone.utc)
    deadline = req.deadline_date
    if deadline and deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)
    overdue = (now > deadline) if deadline else False
    days_left = max(0, (deadline - now).days) if deadline else 0
    return {
        "id": req.id,
        "status": req.status,
        "deadline_date": req.deadline_date,
        "is_overdue": overdue,
        "days_remaining": days_left,
        "message": "Deadline exceeded — follow-up recommended." if overdue else "Within deadline.",
    }


def _to_response(req: ErasureRequest) -> ErasureRequestResponse:
    return ErasureRequestResponse(
        id=req.id,
        case_id=req.case_id,
        dpo_email=req.dpo_email,
        legal_basis=req.legal_basis,
        request_date=req.request_date,
        deadline_date=req.deadline_date,
        status=req.status,
        organization_response=req.organization_response,
        created_at=req.created_at,
    )
