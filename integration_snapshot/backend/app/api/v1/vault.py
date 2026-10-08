"""
S.H.A.D.E. — Vault Router
Role: Member 1 — Core Architecture + Backend + Database + Integration

Endpoints:
  POST   /vault/store           — Encrypt & store a sensitive value
  GET    /vault/token/{token}   — Lookup token metadata (safe metadata only)
  POST   /vault/retrieve        — Retrieve authorized sensitive value
  DELETE /vault/{id}            — Delete sensitive value (cascade-invalidates auth)
  GET    /vault/                — List stored values (tokens/metadata only)

INVARIANTS:
  - All endpoints require an active authenticated session.
  - All operations are strictly isolated to the authenticated owner.
  - Cross-owner access is rejected.
"""

import logging

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.dependencies import SessionContext, get_current_session
from backend.app.core.errors import NotFoundError
from backend.app.database.models import SensitiveValue, SyntheticToken
from backend.app.database.session import get_db
from backend.app.schemas.schemas import (
    DeleteSensitiveValueResponse,
    SensitiveValueResponse,
    StoreSensitiveValueRequest,
    TokenLookupResponse,
)
from backend.app.services.vault_service import VaultService

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/store", response_model=SensitiveValueResponse, summary="Encrypt & store sensitive value")
async def store_sensitive_value(
    body: StoreSensitiveValueRequest,
    session_ctx: SessionContext = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    """
    Encrypt and store a sensitive value in the local vault for the authenticated owner.
    If the same value already exists for this owner, returns the existing token (duplicate reuse).
    Returns only the synthetic token — never the plaintext value.
    """
    vault = VaultService(db)
    sv, token = await vault.store_sensitive_value(
        owner_id=session_ctx.owner.id,
        raw_value=body.raw_value,
        data_type=body.data_type,
    )
    return SensitiveValueResponse(
        id=sv.id,
        data_type=sv.data_type,
        synthetic_token=token.token,
        created_at=sv.created_at,
        deleted_at=sv.deleted_at,
    )


@router.get("/token/{token}", response_model=TokenLookupResponse, summary="Lookup token metadata")
async def lookup_token(
    token: str,
    session_ctx: SessionContext = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    """
    Return metadata for a synthetic token. Only returns metadata if the token
    belongs to the authenticated owner.
    """
    vault = VaultService(db)
    token_record = await vault.lookup_by_token(token)
    if token_record is None:
        return TokenLookupResponse(
            token_id="", synthetic_token=token, data_type="", exists=False
        )

    # Validate that token belongs to this owner
    sv = await db.get(SensitiveValue, token_record.sensitive_value_id)
    if sv is None or sv.deleted_at is not None or sv.owner_id != session_ctx.owner.id:
        return TokenLookupResponse(
            token_id="", synthetic_token=token, data_type="", exists=False
        )

    return TokenLookupResponse(
        token_id=token_record.id,
        synthetic_token=token_record.token,
        data_type=token_record.data_type,
        exists=True,
        created_at=token_record.created_at,
    )


@router.post("/retrieve", summary="Retrieve authorized sensitive value (APPROVED auth required)")
async def retrieve_sensitive_value(
    sensitive_value_id: str,
    authorization_id: str,
    session_ctx: SessionContext = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    """
    Return the decrypted real value. Requires a valid APPROVED authorization_id
    and matching owner identity.
    """
    vault = VaultService(db)
    real_value = await vault.retrieve_sensitive_value(
        sensitive_value_id=sensitive_value_id,
        authorization_id=authorization_id,
        owner_id=session_ctx.owner.id,
    )
    logger.info(
        "[Vault] Sensitive value retrieved sv_id=%s auth_id=%s owner_id=%s",
        sensitive_value_id, authorization_id, session_ctx.owner.id,
    )
    return {"sensitive_value_id": sensitive_value_id, "real_value": real_value}


@router.delete("/{sensitive_value_id}", response_model=DeleteSensitiveValueResponse)
async def delete_sensitive_value(
    sensitive_value_id: str,
    session_ctx: SessionContext = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    """
    Soft-delete a sensitive value and automatically invalidate all APPROVED authorizations.
    Scoped strictly to the authenticated owner.
    """
    vault = VaultService(db)
    count = await vault.delete_sensitive_value(sensitive_value_id, session_ctx.owner.id)
    return DeleteSensitiveValueResponse(
        id=sensitive_value_id,
        deleted=True,
        authorizations_invalidated=count,
    )


@router.get("/", summary="List vault entries (safe metadata only)")
async def list_vault_entries(
    session_ctx: SessionContext = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    """Return list of non-deleted sensitive values belonging to the authenticated owner."""
    result = await db.execute(
        select(SensitiveValue, SyntheticToken)
        .join(SyntheticToken, SyntheticToken.sensitive_value_id == SensitiveValue.id)
        .where(
            SensitiveValue.owner_id == session_ctx.owner.id,
            SensitiveValue.deleted_at.is_(None),
        )
    )
    entries = []
    for sv, tok in result.all():
        entries.append(
            SensitiveValueResponse(
                id=sv.id,
                data_type=sv.data_type,
                synthetic_token=tok.token,
                created_at=sv.created_at,
                deleted_at=sv.deleted_at,
            )
        )
    return {"count": len(entries), "items": entries}
