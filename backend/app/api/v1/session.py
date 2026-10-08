"""
S.H.A.D.E. — Session Router
Role: Member 1 — Core Architecture + Backend + Database + Integration

Endpoints:
  POST /session/create    — Create a new session
  POST /session/validate  — Validate a session token
  POST /session/revoke    — Revoke a session
"""

import logging

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.errors import NotFoundError
from backend.app.database.models import Owner
from backend.app.database.session import get_db
from backend.app.schemas.schemas import SessionCreateResponse, SessionValidationResponse
from backend.app.services.session_service import SessionService

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/create", response_model=SessionCreateResponse)
async def create_session(db: AsyncSession = Depends(get_db)):
    """Create a session for the registered owner (MVP: first owner)."""
    result = await db.execute(select(Owner).where(Owner.is_registered == True).limit(1))
    owner = result.scalar_one_or_none()
    if owner is None:
        raise NotFoundError("No registered owner. Complete registration first.")
    svc = SessionService(db)
    session, token = await svc.create_session(owner.id, owner.device_id)
    return SessionCreateResponse(
        session_id=session.id,
        access_token=token,
        expires_at=session.expires_at,
    )


@router.post("/validate", response_model=SessionValidationResponse)
async def validate_session(token: str, db: AsyncSession = Depends(get_db)):
    svc = SessionService(db)
    session = await svc.validate_session(token)
    return SessionValidationResponse(
        session_id=session.id,
        is_valid=True,
        owner_id=session.owner_id,
        device_id=session.device_id,
        expires_at=session.expires_at,
    )


@router.post("/revoke/{session_id}")
async def revoke_session(session_id: str, db: AsyncSession = Depends(get_db)):
    svc = SessionService(db)
    await svc.revoke_session(session_id)
    return {"session_id": session_id, "revoked": True}
