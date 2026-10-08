"""
S.H.A.D.E. — Erasure Request Router
Role: Member 1 — Core Architecture + Backend + Database + Integration

Statutory data erasure workflow (DPDP Act 2023, Section 12).

INVARIANTS:
  - All routes require authenticated session.
  - Operations are strictly isolated to the authenticated owner.
  - User explicitly reviews and sends requests.
  - 7-day statutory deadline is maintained.
  - Follow-up is available only when response is not received.
"""

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.dependencies import SessionContext, get_current_session
from backend.app.core.errors import NotFoundError
from backend.app.database.models import Case, ErasureRequest, FollowUpRequest
from backend.app.database.session import get_db
from backend.app.schemas.schemas import (
    ErasureRequestCreate,
    ErasureRequestResponse,
    ErasureRequestSendResponse,
    ErasureResponseUpdate,
    FollowUpRequestCreate,
    FollowUpResponse,
)

from backend.app.services.legal_delivery import get_legal_delivery_provider

logger = logging.getLogger(__name__)
router = APIRouter()

_DEADLINE_DAYS = 7


@router.post("/", response_model=ErasureRequestResponse, summary="Create erasure request (DRAFT)")
async def create_erasure_request(
    body: ErasureRequestCreate,
    session_ctx: SessionContext = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    """
    Create a DRAFT erasure request. User reviews before sending.
    Scoped to the authenticated owner's case.
    """
    case = await db.get(Case, body.case_id)
    if case is None or case.owner_id != session_ctx.owner.id:
        raise NotFoundError("Case not found.")

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
async def get_erasure_request(
    erasure_id: str,
    session_ctx: SessionContext = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    req = await db.get(ErasureRequest, erasure_id)
    if req is None:
        raise NotFoundError("Erasure request not found.")
    case = await db.get(Case, req.case_id)
    if case is None or case.owner_id != session_ctx.owner.id:
        raise NotFoundError("Erasure request not found.")
    return _to_response(req)


@router.post(
    "/{erasure_id}/send",
    response_model=ErasureRequestSendResponse,
    summary="User sends the erasure request — starts 7-day deadline",
)
async def send_erasure_request(
    erasure_id: str,
    session_ctx: SessionContext = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    """
    User explicitly confirms they have reviewed and authorize sending the erasure request.
    Dispatches notice via configured LegalRequestDeliveryProvider (SMTP / Dev Simulation).
    Records send date and computes 7-day statutory deadline.
    """
    req = await db.get(ErasureRequest, erasure_id)
    if req is None:
        raise NotFoundError("Erasure request not found.")
    case = await db.get(Case, req.case_id)
    if case is None or case.owner_id != session_ctx.owner.id:
        raise NotFoundError("Erasure request not found.")

    # Prevent accidental duplicate send if already successfully sent
    if req.status == "SENT":
        return ErasureRequestSendResponse(
            id=req.id,
            status=req.status,
            request_date=req.request_date or datetime.now(timezone.utc),
            deadline_date=req.deadline_date or datetime.now(timezone.utc),
            message=f"Erasure request was already sent. 7-day statutory deadline is active.",
        )

    # External delivery dispatch
    delivery_provider = get_legal_delivery_provider()
    recipient = req.dpo_email or "dpo@organization.target"
    subject = f"Statutory Notice under Section 12 of DPDP Act 2023 [Case: {case.id[:8]}]"

    delivery_result = await delivery_provider.send_erasure_notice(
        recipient_email=recipient,
        subject=subject,
        notice_body=req.request_body,
        case_id=case.id,
    )

    now = datetime.now(timezone.utc)
    if delivery_result.success:
        req.request_date = now
        req.deadline_date = now + timedelta(days=_DEADLINE_DAYS)
        req.status = "SENT"
        case.status = "ERASURE_REQUESTED"
        msg = f"Erasure request dispatched successfully via {delivery_result.mode}. 7-day statutory deadline: {req.deadline_date.date()}"
    else:
        req.status = "SEND_FAILED"
        req.organization_response = f"Delivery failed: {delivery_result.error_message}"
        msg = f"Delivery failed: {delivery_result.error_message}. You may review and retry."

    await db.flush()

    logger.info(
        "[Erasure] Request processed id=%s status=%s mode=%s owner=%s",
        erasure_id, req.status, delivery_result.mode, session_ctx.owner.id,
    )
    return ErasureRequestSendResponse(
        id=req.id,
        status=req.status,
        request_date=req.request_date or now,
        deadline_date=req.deadline_date or now,
        message=msg,
    )



@router.post("/{erasure_id}/response", response_model=ErasureRequestResponse)
async def record_response(
    erasure_id: str,
    body: ErasureResponseUpdate,
    session_ctx: SessionContext = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    req = await db.get(ErasureRequest, erasure_id)
    if req is None:
        raise NotFoundError("Erasure request not found.")
    case = await db.get(Case, req.case_id)
    if case is None or case.owner_id != session_ctx.owner.id:
        raise NotFoundError("Erasure request not found.")

    req.organization_response = body.organization_response
    req.status = body.new_status
    if body.new_status == "RESOLVED":
        case.status = "RESOLVED"
    elif body.new_status == "RESPONSE_RECEIVED":
        case.status = "AWAITING_RESPONSE"
    await db.flush()
    return _to_response(req)


@router.post("/{erasure_id}/followup", response_model=FollowUpResponse)
async def create_followup(
    erasure_id: str,
    body: FollowUpRequestCreate,
    session_ctx: SessionContext = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    req = await db.get(ErasureRequest, erasure_id)
    if req is None:
        raise NotFoundError("Erasure request not found.")
    case = await db.get(Case, req.case_id)
    if case is None or case.owner_id != session_ctx.owner.id:
        raise NotFoundError("Erasure request not found.")

    fu = FollowUpRequest(
        erasure_request_id=erasure_id,
        follow_up_body=body.follow_up_body,
        status="SENT",
        sent_at=datetime.now(timezone.utc),
    )
    db.add(fu)
    req.status = "FOLLOW_UP_SENT"
    case.status = "FOLLOW_UP_SENT"
    await db.flush()
    return FollowUpResponse(
        id=fu.id,
        erasure_request_id=fu.erasure_request_id,
        follow_up_body=fu.follow_up_body,
        status=fu.status,
        sent_at=fu.sent_at,
        created_at=fu.created_at,
    )


@router.get("/{erasure_id}/deadline")
async def check_deadline(
    erasure_id: str,
    session_ctx: SessionContext = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    req = await db.get(ErasureRequest, erasure_id)
    if req is None:
        raise NotFoundError("Erasure request not found.")
    case = await db.get(Case, req.case_id)
    if case is None or case.owner_id != session_ctx.owner.id:
        raise NotFoundError("Erasure request not found.")

    if req.deadline_date is None:
        return {"erasure_id": erasure_id, "status": req.status, "deadline_passed": False}

    now = datetime.now(timezone.utc)
    passed = now > req.deadline_date.replace(tzinfo=timezone.utc) if req.deadline_date.tzinfo is None else now > req.deadline_date
    return {
        "erasure_id": erasure_id,
        "deadline_date": req.deadline_date,
        "deadline_passed": passed,
        "follow_up_eligible": passed and req.status == "SENT",
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
