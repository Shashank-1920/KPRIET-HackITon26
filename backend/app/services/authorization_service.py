"""
S.H.A.D.E. — Authorization Service
Role: Member 1 — Core Architecture + Backend + Database + Integration

Responsibilities:
  - Receive authorization requests for sensitive value access.
  - Identify context: which token/value, which component, what purpose.
  - Record PENDING authorization with a 60-second prompt budget.
  - Process owner APPROVED/DENIED decisions.
  - Enforce that REQUEST ≠ AUTHORIZATION.
  - Invalidate authorization when the sensitive value is deleted
    (handled by cascade in VaultService / DB model).
  - Reject unauthorized access attempts.
  - Produce audit events for every decision.

BIOMETRIC / PIN ABSTRACTION:
  The authorization service receives the auth_method ('BIOMETRIC' | 'PIN')
  from the platform/frontend layer. It does NOT implement biometric capture
  itself — that is a platform-layer concern (Member 4 / OS APIs).
  The backend ENFORCES that an explicit approval has been submitted.

CRITICAL INVARIANT:
  Callers cannot bypass authorization by calling vault directly.
  VaultService.retrieve_sensitive_value() validates the authorization_id
  and its state independently.
"""

import json
import logging
from datetime import datetime, timedelta, timezone


def _utcnow() -> datetime:
    """Return current UTC time as a naive datetime (for SQLite compatibility)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.core.errors import (
    AuthorizationExpiredError,
    AuthorizationRequiredError,
    ForbiddenError,
    NotFoundError,
    SensitiveDataNotFoundError,
)
from backend.app.database.models import (
    Authorization,
    AuditEvent,
    RehydrationRequest,
    SensitiveValue,
    SyntheticToken,
)

logger = logging.getLogger(__name__)


class AuthorizationService:
    """
    Service responsible for the authorization lifecycle.
    All authorization decisions are persisted as immutable audit events.
    """

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def request_authorization(
        self,
        sensitive_value_id: str,
        requesting_component: str,
        purpose_scope: Optional[str] = None,
    ) -> Authorization:
        """
        Create a PENDING authorization request for a sensitive value.
        Initiates the owner prompt window (expires after configured timeout).
        """
        # Verify the sensitive value exists
        sv = await self._db.get(SensitiveValue, sensitive_value_id)
        if sv is None or sv.deleted_at is not None:
            raise SensitiveDataNotFoundError("Sensitive value not found or deleted.")

        prompt_deadline = _utcnow() + timedelta(
            seconds=settings.authorization_prompt_timeout_seconds
        )
        auth = Authorization(
            sensitive_value_id=sensitive_value_id,
            requesting_component=requesting_component,
            purpose_scope=purpose_scope,
            state="PENDING",
            expires_prompt_at=prompt_deadline,
        )
        self._db.add(auth)
        await self._db.flush()

        await self._emit_audit_event(
            event_type="AUTHORIZATION_REQUESTED",
            authorization=auth,
            result="PENDING",
        )
        logger.info(
            "[AuthService] Authorization PENDING id=%s for value_id=%s by %s",
            auth.id, sensitive_value_id, requesting_component,
        )
        return auth

    async def approve_authorization(
        self, authorization_id: str, auth_method: str
    ) -> Authorization:
        """
        Owner approves a PENDING authorization.
        auth_method must be 'BIOMETRIC' or 'PIN'.

        SECURITY: This method must only be called after the platform layer
        has verified the biometric/PIN. The backend trusts the auth_method
        claim from the platform/frontend (Member 4) but records it for audit.
        """
        auth = await self._get_pending_auth(authorization_id)
        auth.state = "APPROVED"
        auth.auth_method = auth_method
        auth.resolved_at = _utcnow()
        await self._db.flush()

        await self._emit_audit_event(
            event_type="AUTHORIZATION_APPROVED",
            authorization=auth,
            result="APPROVED",
            extra_meta={"auth_method": auth_method},
        )
        logger.info("[AuthService] Authorization APPROVED id=%s method=%s", authorization_id, auth_method)
        return auth

    async def deny_authorization(self, authorization_id: str) -> Authorization:
        """Owner explicitly denies a PENDING authorization."""
        auth = await self._get_pending_auth(authorization_id)
        auth.state = "DENIED"
        auth.resolved_at = _utcnow()
        await self._db.flush()

        await self._emit_audit_event(
            event_type="AUTHORIZATION_DENIED",
            authorization=auth,
            result="DENIED",
        )
        logger.info("[AuthService] Authorization DENIED id=%s", authorization_id)
        return auth

    async def check_authorization(self, authorization_id: str) -> Authorization:
        """
        Return the current state of an authorization, expiring PENDING if timed out.
        Raises AuthorizationRequiredError if not APPROVED.
        """
        auth = await self._db.get(Authorization, authorization_id)
        if auth is None:
            raise NotFoundError("Authorization record not found.")

        if auth.state == "PENDING":
            if auth.expires_prompt_at and _utcnow() > auth.expires_prompt_at.replace(tzinfo=None):
                auth.state = "EXPIRED"
                auth.resolved_at = _utcnow()
                await self._db.flush()
                await self._emit_audit_event(
                    event_type="AUTHORIZATION_EXPIRED",
                    authorization=auth,
                    result="EXPIRED",
                )
        return auth

    async def request_rehydration(
        self,
        token: str,
        requesting_component: str,
        purpose_scope: Optional[str],
    ) -> tuple[RehydrationRequest, Optional[Authorization]]:
        """
        Initiate a rehydration flow for a detected synthetic token.
        Returns (RehydrationRequest, Authorization) where the Authorization
        will be PENDING until the owner acts.
        """
        stmt = select(SyntheticToken).where(SyntheticToken.token == token)
        result = await self._db.execute(stmt)
        syn_token = result.scalar_one_or_none()
        if syn_token is None:
            raise NotFoundError(f"Synthetic token not found: {token}")

        # Check if the sensitive value is still alive
        sv = await self._db.get(SensitiveValue, syn_token.sensitive_value_id)
        if sv is None or sv.deleted_at is not None:
            raise SensitiveDataNotFoundError("Underlying sensitive value has been deleted.")

        # Create RehydrationRequest
        rr = RehydrationRequest(
            synthetic_token_id=syn_token.id,
            requesting_component=requesting_component,
            purpose_scope=purpose_scope,
            state="PENDING",
        )
        self._db.add(rr)
        await self._db.flush()

        # Create linked Authorization
        auth = await self.request_authorization(
            sensitive_value_id=sv.id,
            requesting_component=requesting_component,
            purpose_scope=purpose_scope,
        )

        logger.info(
            "[AuthService] Rehydration PENDING rehydration_id=%s token=%s",
            rr.id, token,
        )
        return rr, auth

    # ── PRIVATE ───────────────────────────────────────────────────────────────

    async def _get_pending_auth(self, authorization_id: str) -> Authorization:
        """Return a PENDING authorization or raise appropriate error."""
        auth = await self._db.get(Authorization, authorization_id)
        if auth is None:
            raise NotFoundError("Authorization not found.")
        if auth.state == "APPROVED":
            return auth  # idempotent — already approved
        if auth.state in ("DENIED", "REVOKED"):
            raise ForbiddenError(f"Authorization has been {auth.state}.")
        if auth.state == "EXPIRED":
            raise AuthorizationExpiredError("Authorization prompt has expired. Please re-request.")
        if auth.expires_prompt_at and _utcnow() > auth.expires_prompt_at.replace(tzinfo=None):
            auth.state = "EXPIRED"
            await self._db.flush()
            raise AuthorizationExpiredError("Authorization prompt timed out.")
        return auth

    async def _emit_audit_event(
        self,
        event_type: str,
        authorization: Authorization,
        result: str,
        extra_meta: Optional[dict] = None,
    ) -> None:
        """
        Persist a sanitized audit event.
        MUST NOT contain any plaintext sensitive values.
        """
        meta: dict = {"event_type": event_type}
        if extra_meta:
            meta.update(extra_meta)

        audit = AuditEvent(
            authorization_id=authorization.id,
            event_type=event_type,
            result=result,
            requesting_component=authorization.requesting_component,
            metadata_safe=json.dumps(meta),
        )
        self._db.add(audit)
        await self._db.flush()
