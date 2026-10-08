"""
S.H.A.D.E. — Authorization Service
Role: Member 1 — Core Architecture + Backend + Database + Integration

Responsibilities:
  - Receive authorization requests for sensitive value access.
  - Identify context: which token/value, which component, what purpose.
  - Record PENDING authorization with a 60-second prompt budget.
  - Enforce challenge-response owner authentication (Biometric assertions or Argon2id PIN).
  - Enforce that REQUEST ≠ AUTHORIZATION.
  - Invalidate authorization when the sensitive value is deleted.
  - Reject unauthorized and cross-owner access attempts.
  - Produce audit events for every decision without logging secrets.

CRITICAL INVARIANTS:
  - Client-supplied strings such as "auth_method": "BIOMETRIC" are NEVER trusted as proof.
  - Raw biometrics are NEVER accepted or stored.
  - Real value exposure is strictly prevented without verified approval.
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.core.errors import (
    AuthorizationExpiredError,
    AuthorizationRequiredError,
    ForbiddenError,
    NotFoundError,
    SensitiveDataNotFoundError,
    UnauthorizedError,
)
from backend.app.database.models import (
    AuditEvent,
    Authorization,
    Owner,
    RehydrationRequest,
    SensitiveValue,
    SyntheticToken,
)
from backend.app.services.auth_provider import AuthChallenge, get_auth_provider

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    """Return current UTC time as a naive datetime (for SQLite compatibility)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class AuthorizationService:
    """
    Service responsible for the authorization lifecycle and verified owner assertions.
    """

    def __init__(self, db: AsyncSession) -> None:
        self._db = db
        self._auth_provider = get_auth_provider()

    async def request_authorization(
        self,
        sensitive_value_id: str,
        requesting_component: str,
        purpose_scope: Optional[str] = None,
        owner_id: Optional[str] = None,
    ) -> Authorization:
        """
        Create a PENDING authorization request for a sensitive value.
        Initiates the owner prompt window (expires after configured timeout).
        """
        sv = await self._db.get(SensitiveValue, sensitive_value_id)
        if sv is None or sv.deleted_at is not None:
            raise SensitiveDataNotFoundError("Sensitive value not found or deleted.")

        if owner_id and sv.owner_id != owner_id:
            raise ForbiddenError("Cannot request authorization for another owner's sensitive value.")

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

    async def create_challenge(self, authorization_id: str, owner_id: str) -> AuthChallenge:
        """Create a single-use time-bound challenge for owner authorization approval."""
        auth = await self._get_pending_auth(authorization_id)
        sv = await self._db.get(SensitiveValue, auth.sensitive_value_id)
        if sv is None or sv.deleted_at is not None:
            raise SensitiveDataNotFoundError("Underlying sensitive value has been deleted.")
        if sv.owner_id != owner_id:
            raise ForbiddenError("Cannot create challenge for another owner's authorization.")

        return self._auth_provider.create_challenge(
            owner_id=owner_id,
            action="AUTHORIZE_SENSITIVE_VALUE",
            resource_id=authorization_id,
        )

    async def approve_authorization(
        self,
        authorization_id: str,
        auth_method: str,
        challenge_id: Optional[str] = None,
        assertion: Optional[Any] = None,
        owner: Optional[Owner] = None,
    ) -> Authorization:
        """
        Owner approves a PENDING authorization after verifying authentication assertion.
        Rejects unverified or client-faked authentication proofs.
        """
        auth = await self._get_pending_auth(authorization_id)
        sv = await self._db.get(SensitiveValue, auth.sensitive_value_id)
        if sv is None or sv.deleted_at is not None:
            auth.state = "REVOKED"
            await self._db.flush()
            raise SensitiveDataNotFoundError("Associated sensitive value has been deleted. Authorization revoked.")

        if owner and sv.owner_id != owner.id:
            raise ForbiddenError("Cannot approve authorization for another owner's sensitive value.")

        # Enforce assertion verification
        normalized_method = (auth_method or "").upper().strip()
        if normalized_method == "BIOMETRIC":
            if not challenge_id or assertion is None:
                raise UnauthorizedError("Biometric approval requires a valid challenge_id and assertion.")
            verified = self._auth_provider.verify_biometric_assertion(
                challenge_id=challenge_id,
                assertion=assertion,
                owner_id=owner.id if owner else None,
            )
            if not verified:
                raise UnauthorizedError("Biometric authentication assertion verification failed.")

        elif normalized_method == "PIN":
            if owner is None:
                raise UnauthorizedError("Owner context required for PIN verification.")
            if assertion is None:
                raise UnauthorizedError("PIN verification requires PIN assertion.")
            verified = self._auth_provider.verify_pin_assertion(
                owner=owner,
                pin_input=str(assertion),
                challenge_id=challenge_id,
            )
            if not verified:
                raise UnauthorizedError("PIN verification failed.")
        else:
            raise UnauthorizedError(f"Unsupported authentication method: '{auth_method}'.")

        auth.state = "APPROVED"
        auth.auth_method = normalized_method
        auth.resolved_at = _utcnow()
        await self._db.flush()

        await self._emit_audit_event(
            event_type="AUTHORIZATION_APPROVED",
            authorization=auth,
            result="APPROVED",
            extra_meta={"auth_method": normalized_method},
        )
        logger.info("[AuthService] Authorization APPROVED id=%s method=%s", authorization_id, normalized_method)
        return auth

    async def deny_authorization(
        self, authorization_id: str, owner_id: Optional[str] = None
    ) -> Authorization:
        """Owner explicitly denies a PENDING authorization."""
        auth = await self._get_pending_auth(authorization_id)
        sv = await self._db.get(SensitiveValue, auth.sensitive_value_id)
        if owner_id and sv and sv.owner_id != owner_id:
            raise ForbiddenError("Cannot deny authorization for another owner.")

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

    async def check_authorization(
        self, authorization_id: str, owner_id: Optional[str] = None
    ) -> Authorization:
        """
        Return the current state of an authorization.
        Invalidates (REVOKED) if the underlying sensitive value was deleted.
        """
        auth = await self._db.get(Authorization, authorization_id)
        if auth is None:
            raise NotFoundError("Authorization record not found.")

        sv = await self._db.get(SensitiveValue, auth.sensitive_value_id)
        if sv is None or sv.deleted_at is not None:
            if auth.state != "REVOKED":
                auth.state = "REVOKED"
                await self._db.flush()
            return auth

        if owner_id and sv.owner_id != owner_id:
            raise ForbiddenError("Cannot inspect another owner's authorization record.")

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
        owner_id: Optional[str] = None,
    ) -> tuple[RehydrationRequest, Optional[Authorization]]:
        """
        Initiate a rehydration flow for a detected synthetic token.
        """
        stmt = select(SyntheticToken).where(SyntheticToken.token == token)
        result = await self._db.execute(stmt)
        syn_token = result.scalar_one_or_none()
        if syn_token is None:
            raise NotFoundError(f"Synthetic token not found: {token}")

        sv = await self._db.get(SensitiveValue, syn_token.sensitive_value_id)
        if sv is None or sv.deleted_at is not None:
            raise SensitiveDataNotFoundError("Underlying sensitive value has been deleted.")

        if owner_id and sv.owner_id != owner_id:
            raise ForbiddenError("Cannot request rehydration for another owner's token.")

        rr = RehydrationRequest(
            synthetic_token_id=syn_token.id,
            requesting_component=requesting_component,
            purpose_scope=purpose_scope,
            state="PENDING",
        )
        self._db.add(rr)
        await self._db.flush()

        auth = await self.request_authorization(
            sensitive_value_id=sv.id,
            requesting_component=requesting_component,
            purpose_scope=purpose_scope,
            owner_id=owner_id,
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
            return auth
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
        """Persist a sanitized audit event without raw secrets."""
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
