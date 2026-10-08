"""
S.H.A.D.E. — Auth & Owner Registration Router
Role: Member 1 — Core Architecture + Backend + Database + Integration

Endpoints:
  POST /auth/register         — Step 1: Submit mobile number, receive OTP
  POST /auth/verify-otp       — Step 2: Verify OTP
  POST /auth/bind-device      — Step 3: Bind vault to device
  GET  /auth/status           — Owner registration status
"""

import hashlib
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.errors import DeviceNotBoundError, InvalidRequestError, UnauthorizedError
from backend.app.database.models import Device, Owner
from backend.app.database.session import get_db
from backend.app.schemas.schemas import (
    DeviceBindingRequest,
    OTPVerificationRequest,
    OwnerRegistrationRequest,
    OwnerStatusResponse,
    SessionCreateResponse,
)
from backend.app.services.otp_provider import get_otp_provider
from backend.app.services.session_service import SessionService

logger = logging.getLogger(__name__)
router = APIRouter()


def _hash_mobile(mobile: str) -> str:
    return hashlib.sha256(mobile.encode()).hexdigest()


@router.post("/register", summary="Step 1: Register mobile number & send OTP")
async def register_owner(
    body: OwnerRegistrationRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Begin owner registration. Sends OTP to the provided mobile number.
    Mobile number is hashed immediately — not stored in plaintext.
    """
    mobile_hash = _hash_mobile(body.mobile_number)
    existing = await db.execute(select(Owner).where(Owner.mobile_hash == mobile_hash))
    if existing.scalar_one_or_none():
        raise InvalidRequestError("An owner with this mobile number is already registered.")

    otp_provider = get_otp_provider()
    if hasattr(otp_provider, "has_pending_otp") and otp_provider.has_pending_otp(body.mobile_number):
        raise InvalidRequestError("A registration OTP has already been sent to this mobile number.")

    sent = await otp_provider.send_otp(body.mobile_number)
    if not sent:
        from backend.app.core.errors import ExternalServiceUnavailableError
        raise ExternalServiceUnavailableError("OTP service is currently unavailable.")

    return {"message": "OTP sent successfully.", "next_step": "POST /auth/verify-otp"}


@router.post("/verify-otp", summary="Step 2: Verify OTP")
async def verify_otp(
    body: OTPVerificationRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Verify the OTP. On success, returns verification ticket for device binding.
    """
    otp_provider = get_otp_provider()
    valid, ticket = await otp_provider.verify_otp(body.mobile_number, body.otp_code)
    if not valid:
        raise UnauthorizedError("OTP verification failed. Invalid or expired code.")

    return {
        "message": "OTP verified successfully.",
        "next_step": "POST /auth/bind-device",
        "mobile_verified": True,
        "verification_ticket": ticket,
    }


@router.post("/bind-device", summary="Step 3: Bind vault to this device")
async def bind_device(
    body: DeviceBindingRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Bind the vault to the current device and create the owner record.
    Owner mobile_hash is resolved from the verified OTP ticket.
    """
    # Create or retrieve device
    result = await db.execute(
        select(Device).where(Device.device_fingerprint_hash == body.device_fingerprint_hash)
    )
    device = result.scalar_one_or_none()
    if device is None:
        device = Device(
            device_fingerprint_hash=body.device_fingerprint_hash,
            platform=body.platform,
            is_bound=True,
            bound_at=datetime.now(timezone.utc),
        )
        db.add(device)
        await db.flush()
    elif device.is_bound:
        raise InvalidRequestError("This device is already bound to a vault.")

    otp_provider = get_otp_provider()
    if body.verification_ticket and hasattr(otp_provider, "verify_ticket"):
        mobile_hash = otp_provider.verify_ticket(body.verification_ticket)
    elif body.mobile_number:
        from backend.app.core.crypto import compute_lookup_hash
        mobile_hash = compute_lookup_hash(body.mobile_number)
    else:
        from backend.app.core.crypto import compute_lookup_hash
        mobile_hash = compute_lookup_hash(body.device_fingerprint_hash)

    # Check duplicate owner
    existing_owner = await db.execute(select(Owner).where(Owner.mobile_hash == mobile_hash))
    if existing_owner.scalar_one_or_none():
        raise InvalidRequestError("An owner with this verified mobile identity is already registered.")

    owner = Owner(
        device_id=device.id,
        mobile_hash=mobile_hash,
        pin_hash=body.pin_hash,
        is_registered=True,
        registered_at=datetime.now(timezone.utc),
    )
    db.add(owner)
    device.is_bound = True
    device.bound_at = datetime.now(timezone.utc)
    await db.flush()

    logger.info("[Auth] Owner registered and device bound. device_id=%s owner_id=%s", device.id, owner.id)
    return {
        "message": "Device bound successfully. Vault initialized.",
        "owner_id": owner.id,
        "device_id": device.id,
    }


@router.get("/status", response_model=OwnerStatusResponse, summary="Owner registration status")
async def owner_status(db: AsyncSession = Depends(get_db)):
    """Return registration and device-binding status of the first owner record."""
    result = await db.execute(select(Owner).limit(1))
    owner = result.scalar_one_or_none()
    if owner is None:
        return OwnerStatusResponse(
            owner_id="",
            is_registered=False,
            device_is_bound=False,
            registered_at=None,
        )
    device = await db.get(Device, owner.device_id)
    return OwnerStatusResponse(
        owner_id=owner.id,
        is_registered=owner.is_registered,
        device_is_bound=device.is_bound if device else False,
        registered_at=owner.registered_at,
    )
