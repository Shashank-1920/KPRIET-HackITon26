"""
S.H.A.D.E. — Clipboard / DLP Integration Router
Role: Member 1 — Core Architecture + Backend + Database + Integration

Integration Contract for Member 2 (Security + DLP).

Member 2's DLP engine calls these endpoints to:
  1. Submit clipboard content → backend tokenizes if sensitive.
  2. Backend returns: synthetic token (if sensitive) or PASSTHROUGH (if clean).

The backend is the ONLY entry point for raw sensitive content.
It encrypts immediately upon receipt — Member 2 should not store raw values.

Endpoints:
  POST /clipboard/submit     — Submit clipboard content for DLP processing
"""

import logging

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.errors import NotFoundError
from backend.app.database.models import Owner
from backend.app.database.session import get_db
from backend.app.schemas.schemas import ClipboardSubmitRequest, ClipboardSubmitResponse
from backend.app.services.vault_service import VaultService

logger = logging.getLogger(__name__)
router = APIRouter()

# Data types that Member 2 DLP may detect
_SUPPORTED_TYPES = {
    "AADHAAR", "PAN", "PASSWORD", "API_KEY", "MOBILE", "EMAIL",
    "CREDIT_CARD", "UPI_ID", "VEHICLE_PLATE", "URL_WITH_SECRET", "OTHER",
}


@router.post(
    "/submit",
    response_model=ClipboardSubmitResponse,
    summary="Submit clipboard content for DLP tokenization",
)
async def submit_clipboard_content(
    body: ClipboardSubmitRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    **Integration Contract for Member 2 (DLP Engine)**

    Member 2 calls this endpoint after detecting that clipboard content
    may be sensitive. The backend:

    1. If `detected_type` is None (Member 2 found nothing sensitive):
       - Returns `PASSTHROUGH`. Clipboard is left unchanged.

    2. If `detected_type` is set (Member 2 detected a sensitive value):
       - Backend checks for an existing mapping (lookup_hash).
       - If same value exists → reuses existing token (REUSED).
       - If new value → encrypts, stores, generates 12-char token (TOKENIZED).
       - Returns the synthetic token.

    **Never returns the original sensitive content.**

    Request Fields:
    - `content`            : The clipboard text (may contain sensitive data).
    - `detected_type`      : Data type from Member 2 DLP. None = no detection.
    - `detection_confidence`: Confidence score from Member 2 (0.0–1.0).
    - `detection_metadata` : Additional context from Member 2.
    """
    # If Member 2 found nothing sensitive, pass through unchanged
    if body.detected_type is None:
        logger.debug("[Clipboard] No sensitive detection — PASSTHROUGH.")
        return ClipboardSubmitResponse(
            is_sensitive=False,
            synthetic_token=None,
            data_type=None,
            action="PASSTHROUGH",
        )

    data_type = body.detected_type.upper()
    if data_type not in _SUPPORTED_TYPES:
        data_type = "OTHER"

    # Retrieve owner for vault operation
    result = await db.execute(select(Owner).where(Owner.is_registered == True).limit(1))
    owner = result.scalar_one_or_none()
    if owner is None:
        raise NotFoundError("No registered owner. Complete registration first.")

    vault = VaultService(db)
    from backend.app.core.crypto import compute_lookup_hash
    lookup_hash = compute_lookup_hash(body.content)
    existing = await vault._find_by_hash(owner.id, lookup_hash)
    action = "REUSED" if existing is not None else "TOKENIZED"

    sv, token = await vault.store_sensitive_value(
        owner_id=owner.id,
        raw_value=body.content,
        data_type=data_type,
    )

    logger.info(
        "[Clipboard] Sensitive content %s: type=%s token=%s",
        action, data_type, token.token,
    )
    return ClipboardSubmitResponse(
        is_sensitive=True,
        synthetic_token=token.token,
        data_type=data_type,
        action=action,
    )
