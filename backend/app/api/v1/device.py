"""
S.H.A.D.E. — Device Router
Role: Member 1 — Core Architecture + Backend + Database + Integration

Endpoints:
  GET /device/status — Device binding and vault status
"""

import logging

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database.models import Device, Owner
from backend.app.database.session import get_db
from backend.app.schemas.schemas import DeviceStatusResponse

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/status", response_model=DeviceStatusResponse, summary="Device binding & vault status")
async def device_status(db: AsyncSession = Depends(get_db)):
    """Return the current device binding status and vault initialization state."""
    result = await db.execute(select(Device).limit(1))
    device = result.scalar_one_or_none()
    if device is None:
        return DeviceStatusResponse(
            device_id="",
            platform="unknown",
            is_bound=False,
            bound_at=None,
            vault_status="NOT_INITIALIZED",
        )
    return DeviceStatusResponse(
        device_id=device.id,
        platform=device.platform,
        is_bound=device.is_bound,
        bound_at=device.bound_at,
        vault_status="UNLOCKED" if device.is_bound else "LOCKED",
    )
