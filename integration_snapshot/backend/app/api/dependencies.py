"""
S.H.A.D.E. — FastAPI API Dependencies
Role: Member 1 — Core Architecture + Backend + Database + Integration

Provides authentication and owner isolation dependencies:
- get_current_session: Enforces valid session, bound device, and authenticated owner.
- SessionContext: Bundles the authenticated Owner, Device, and Session models.

INVARIANTS:
- Every protected endpoint MUST depend on get_current_session.
- All database operations on protected endpoints MUST be scoped to session_ctx.owner.id.
- Cross-owner data access is strictly prohibited and fails with 401/403/404.
"""

from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, Header, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.errors import DeviceNotBoundError, UnauthorizedError
from backend.app.database.models import Device, Owner, Session
from backend.app.database.session import get_db
from backend.app.services.device_attestation import get_device_attestation_provider
from backend.app.services.session_service import SessionService


@dataclass
class SessionContext:
    """Holds the verified identity context for the current request."""
    owner: Owner
    device: Device
    session: Session


async def get_current_session(
    request: Request,
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    x_session_token: Optional[str] = Header(default=None, alias="X-Session-Token"),
    x_device_id: Optional[str] = Header(default=None, alias="X-Device-Id"),
    db: AsyncSession = Depends(get_db),
) -> SessionContext:
    """
    Authenticate the current request against an active session.

    Accepts session token from:
    1. Authorization: Bearer <token>
    2. X-Session-Token: <token>

    Validates:
    - Token authenticity, signature, and expiration.
    - Session active status (not revoked).
    - Device binding and attestation.
    - Owner existence and registration.
    """
    token: Optional[str] = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()
    elif x_session_token:
        token = x_session_token.strip()

    if not token:
        raise UnauthorizedError("Authentication required: Missing Bearer or X-Session-Token header.")

    svc = SessionService(db)
    session = await svc.validate_session(token)

    # Validate device binding
    device = await db.get(Device, session.device_id)
    if device is None or not device.is_bound:
        raise DeviceNotBoundError("Session is bound to an invalid or unbound device.")

    if x_device_id and x_device_id.strip() != device.id:
        raise UnauthorizedError(f"Device mismatch: requested device does not match session device.")

    # Verify device attestation
    attestation_provider = get_device_attestation_provider()
    is_valid_device = await attestation_provider.verify_device_binding(
        device=device,
        client_device_id=x_device_id.strip() if x_device_id else device.id,
    )
    if not is_valid_device:
        raise UnauthorizedError("Device attestation verification failed.")

    # Validate owner
    owner = await db.get(Owner, session.owner_id)
    if owner is None or not owner.is_registered:
        raise UnauthorizedError("Session is associated with an unverified or nonexistent owner.")

    return SessionContext(owner=owner, device=device, session=session)
