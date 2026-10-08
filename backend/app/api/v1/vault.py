"""
S.H.A.D.E. — Vault Router
Role: Member 1 — Core Architecture + Backend + Database + Integration

Endpoints:
  POST   /vault/store           — Encrypt & store a sensitive value
  GET    /vault/{token}         — Lookup token metadata (no plaintext)
  POST   /vault/retrieve        — Retrieve authorized sensitive value
  DELETE /vault/{id}            — Delete sensitive value (cascade-invalidates auth)
  GET    /vault/                — List stored values (tokens/metadata only)
"""

import logging

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.errors import NotFoundError
from backend.app.database.models import Owner, SensitiveValue, SyntheticToken
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


async def _get_first_owner(db: AsyncSession) -> Owner:
    """MVP helper: get the single owner. Production uses JWT session."""
    result = await db.execute(select(Owner).where(Owner.is_registered == True).limit(1))
    owner = result.scalar_one_or_none()
    if owner is None:
        raise NotFoundError("No registered owner found. Complete registration first.")
    return owner


@router.post("/store", response_model=SensitiveValueResponse, summary="Encrypt & store sensitive value")
async def store_sensitive_value(
    body: StoreSensitiveValueRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Encrypt and store a sensitive value in the local vault.
    If the same value already exists, returns the existing token (duplicate reuse).
    Returns only the synthetic token — never the plaintext value.
    """
    owner = await _get_first_owner(db)
    vault = VaultService(db)
    sv, token = await vault.store_sensitive_value(
        owner_id=owner.id,
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
async def lookup_token(token: str, db: AsyncSession = Depends(get_db)):
    """
    Return metadata for a synthetic token. Never returns the plaintext value.
    """
    vault = VaultService(db)
    token_record = await vault.lookup_by_token(token)
    if token_record is None:
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
    db: AsyncSession = Depends(get_db),
):
    """
    Return the decrypted real value. Requires a valid APPROVED authorization_id.
    This endpoint enforces authorization server-side — frontend authorization flags
    are never trusted for this operation.
    NEVER forward the real_value to external systems.
    """
    vault = VaultService(db)
    real_value = await vault.retrieve_sensitive_value(sensitive_value_id, authorization_id)
    # Return value only in controlled response; log only safe identifiers
    logger.info(
        "[Vault] Sensitive value retrieved sv_id=%s auth_id=%s",
        sensitive_value_id, authorization_id,
    )
    return {"sensitive_value_id": sensitive_value_id, "real_value": real_value}


@router.delete("/{sensitive_value_id}", response_model=DeleteSensitiveValueResponse)
async def delete_sensitive_value(
    sensitive_value_id: str, db: AsyncSession = Depends(get_db)
):
    """
    Soft-delete a sensitive value and automatically invalidate all APPROVED authorizations.
    """
    owner = await _get_first_owner(db)
    vault = VaultService(db)
    count = await vault.delete_sensitive_value(sensitive_value_id, owner.id)
    return DeleteSensitiveValueResponse(
        id=sensitive_value_id,
        deleted=True,
        authorizations_invalidated=count,
    )


@router.get("/", summary="List vault entries (safe metadata only)")
async def list_vault_entries(db: AsyncSession = Depends(get_db)):
    """Return list of all non-deleted sensitive values as safe metadata (tokens, types, dates)."""
    owner = await _get_first_owner(db)
    result = await db.execute(
        select(SensitiveValue, SyntheticToken)
        .join(SyntheticToken, SyntheticToken.sensitive_value_id == SensitiveValue.id)
        .where(
            SensitiveValue.owner_id == owner.id,
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
    return {"count": len(entries), "entries": entries}
