"""
S.H.A.D.E. — Clipboard / DLP Integration Router
Role: Member 1 — Core Architecture + Backend + Database + Integration

Integration Contract for Member 2 (Security + DLP).

Member 2's DLP engine calls these endpoints to:
  1. Submit clipboard content → backend tokenizes if sensitive.
  2. Backend returns: synthetic token (if sensitive) or PASSTHROUGH (if clean).

INVARIANTS:
  - Requires authenticated session.
  - Stored values are scoped to the authenticated owner.
  - Normal text is passed through without modification or storage.
  - Sensitive values are encrypted immediately.
"""

import logging

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.dependencies import SessionContext, get_current_session
from backend.app.core.crypto import compute_lookup_hash
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
    session_ctx: SessionContext = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    """
    Integration Contract for Member 2 (DLP Engine)
    Processes clipboard content scoped to the active authenticated owner.
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

    owner_id = session_ctx.owner.id
    vault = VaultService(db)
    lookup_hash = compute_lookup_hash(body.content)
    existing = await vault._find_by_hash(owner_id, lookup_hash)
    action = "REUSED" if existing is not None else "TOKENIZED"

    sv, token = await vault.store_sensitive_value(
        owner_id=owner_id,
        raw_value=body.content,
        data_type=data_type,
    )

    logger.info(
        "[Clipboard] Sensitive content %s: type=%s token=%s owner_id=%s",
        action, data_type, token.token, owner_id,
    )
    return ClipboardSubmitResponse(
        is_sensitive=True,
        synthetic_token=token.token,
        data_type=data_type,
        action=action,
    )
