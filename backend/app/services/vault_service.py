"""
S.H.A.D.E. — Vault Service
Role: Member 1 — Core Architecture + Backend + Database + Integration

The Vault Service is the SOLE authorized path for reading and writing
encrypted sensitive values. All other application code must use this service.
Direct manipulation of encrypted database records from outside this service
is prohibited.

Responsibilities:
  - Encrypt sensitive values before storage (AES-256-GCM via crypto module).
  - Decrypt authorized sensitive values.
  - Store token mappings.
  - Find existing mappings (by lookup_hash — no plaintext comparison).
  - Delete sensitive values (cascades to invalidate authorizations via DB cascade).
  - Prevent unauthorized access (must hold APPROVED authorization to decrypt).

SERVICE BOUNDARY:
  This service does NOT make authorization decisions.
  It ENFORCES that an APPROVED authorization exists before decrypting.
  Authorization decisions are made by AuthorizationService.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.app.core.crypto import compute_lookup_hash, decrypt_value, encrypt_value
from backend.app.core.errors import (
    AuthorizationRequiredError,
    NotFoundError,
    SensitiveDataNotFoundError,
)
from backend.app.core.keystore import get_key_store
from backend.app.database.models import Authorization, Owner, SensitiveValue, SyntheticToken
from backend.app.services.token_service import TokenService

logger = logging.getLogger(__name__)


class VaultService:
    """
    Centralized service for all encrypted-vault operations.
    Injected with a database session and the key store.
    """

    def __init__(self, db: AsyncSession) -> None:
        self._db = db
        self._key_store = get_key_store()
        self._token_service = TokenService(db)

    # ── WRITE ─────────────────────────────────────────────────────────────────

    async def store_sensitive_value(
        self,
        owner_id: str,
        raw_value: str,
        data_type: str,
    ) -> tuple[SensitiveValue, SyntheticToken]:
        """
        Encrypt and store a sensitive value in the vault.
        If the same value already exists (lookup_hash match), reuse the existing record.

        Returns:
            (SensitiveValue, SyntheticToken) — the stored record and its 12-char token.
        """
        lookup_hash = compute_lookup_hash(raw_value)

        # Check for existing record (duplicate reuse invariant)
        existing = await self._find_by_hash(owner_id, lookup_hash)
        if existing is not None:
            token = await self._token_service.get_or_create_token(existing)
            logger.info(
                "[VaultService] Duplicate value detected (hash=%s...). Reusing token=%s",
                lookup_hash[:8], token.token,
            )
            return existing, token

        # Encrypt and persist
        key = self._key_store.get_master_key()
        encrypted_blob = encrypt_value(raw_value, key)

        sv = SensitiveValue(
            owner_id=owner_id,
            data_type=data_type,
            encrypted_blob=encrypted_blob,
            lookup_hash=lookup_hash,
        )
        self._db.add(sv)
        await self._db.flush()

        token = await self._token_service.get_or_create_token(sv)
        logger.info(
            "[VaultService] Stored new sensitive value id=%s type=%s token=%s",
            sv.id, data_type, token.token,
        )
        return sv, token

    # ── READ (authorized only) ────────────────────────────────────────────────

    async def retrieve_sensitive_value(
        self, sensitive_value_id: str, authorization_id: str
    ) -> str:
        """
        Decrypt and return the real sensitive value.
        Requires a valid APPROVED authorization.

        SECURITY: This method ENFORCES authorization. Callers cannot bypass it.
        """
        # Verify the authorization is APPROVED
        auth = await self._db.get(Authorization, authorization_id)
        if auth is None or auth.state != "APPROVED":
            raise AuthorizationRequiredError(
                "An APPROVED authorization is required to access this sensitive value."
            )
        if auth.sensitive_value_id != sensitive_value_id:
            raise AuthorizationRequiredError(
                "Authorization does not match the requested sensitive value."
            )

        sv = await self._get_active_value(sensitive_value_id)
        key = self._key_store.get_master_key()
        plaintext = decrypt_value(sv.encrypted_blob, key)
        logger.info(
            "[VaultService] Sensitive value retrieved under authorization_id=%s",
            authorization_id,
        )
        # Plaintext is returned to the caller but NEVER logged.
        return plaintext

    # ── DELETE ────────────────────────────────────────────────────────────────

    async def delete_sensitive_value(self, sensitive_value_id: str, owner_id: str) -> int:
        """
        Soft-delete a sensitive value and cascade-invalidate its authorizations.
        Returns the number of authorizations that were invalidated.

        CASCADE RULE: Deleting the record invalidates ALL associated APPROVED authorizations.
        """
        sv = await self._get_active_value(sensitive_value_id)
        if sv.owner_id != owner_id:
            raise NotFoundError("Sensitive value not found for this owner.")

        # Count APPROVED authorizations that will be invalidated
        auth_result = await self._db.execute(
            select(Authorization).where(
                Authorization.sensitive_value_id == sensitive_value_id,
                Authorization.state == "APPROVED",
            )
        )
        approved_auths = auth_result.scalars().all()
        count = len(approved_auths)

        # Invalidate (REVOKED) all approvals
        for auth in approved_auths:
            auth.state = "REVOKED"
            auth.resolved_at = datetime.now(timezone.utc)

        # Soft-delete the sensitive value
        sv.deleted_at = datetime.now(timezone.utc)
        await self._db.flush()

        logger.info(
            "[VaultService] Soft-deleted sensitive_value_id=%s, "
            "invalidated %d authorization(s).",
            sensitive_value_id, count,
        )
        return count

    # ── LOOKUP ────────────────────────────────────────────────────────────────

    async def lookup_by_token(self, token: str) -> Optional[SyntheticToken]:
        """Return the SyntheticToken record for a 12-char token string."""
        return await self._token_service.lookup_by_token(token)

    async def get_value_by_id(self, sensitive_value_id: str) -> SensitiveValue:
        """Return a non-deleted SensitiveValue by ID."""
        return await self._get_active_value(sensitive_value_id)

    # ── PRIVATE ───────────────────────────────────────────────────────────────

    async def _find_by_hash(
        self, owner_id: str, lookup_hash: str
    ) -> Optional[SensitiveValue]:
        """Find an existing active sensitive value by its lookup hash."""
        stmt = select(SensitiveValue).where(
            SensitiveValue.owner_id == owner_id,
            SensitiveValue.lookup_hash == lookup_hash,
            SensitiveValue.deleted_at.is_(None),
        )
        result = await self._db.execute(stmt)
        return result.scalar_one_or_none()

    async def _get_active_value(self, sensitive_value_id: str) -> SensitiveValue:
        """Return a non-deleted SensitiveValue or raise SensitiveDataNotFoundError."""
        sv = await self._db.get(SensitiveValue, sensitive_value_id)
        if sv is None or sv.deleted_at is not None:
            raise SensitiveDataNotFoundError(
                f"Sensitive value not found or has been deleted."
            )
        return sv
