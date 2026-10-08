"""
S.H.A.D.E. — Session Service
Role: Member 1 — Core Architecture + Backend + Database + Integration

Provides secure session management using JWT tokens.
Sessions are device-bound: a session created on device A cannot be used on device B.
"""

import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.core.config import settings
from backend.app.core.errors import UnauthorizedError
from backend.app.database.models import Session

logger = logging.getLogger(__name__)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class SessionService:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    def _get_secret(self) -> str:
        if settings.shade_jwt_secret:
            return settings.shade_jwt_secret
        from backend.app.core.keystore import get_key_store
        return get_key_store().get_jwt_secret()

    async def create_session(self, owner_id: str, device_id: str) -> tuple[Session, str]:
        """Create a new session and return (Session record, JWT token string)."""
        secret = self._get_secret()
        expires_at = datetime.now(timezone.utc) + timedelta(
            minutes=settings.shade_access_token_expire_minutes
        )
        payload = {
            "sub": owner_id,
            "device_id": device_id,
            "jti": secrets.token_hex(16),
            "iat": datetime.now(timezone.utc),
            "exp": expires_at,
        }
        token_str = jwt.encode(payload, secret, algorithm=settings.shade_jwt_algorithm)
        token_hash = _hash_token(token_str)

        session = Session(
            owner_id=owner_id,
            device_id=device_id,
            token_hash=token_hash,
            expires_at=expires_at,
        )
        self._db.add(session)
        await self._db.flush()
        return session, token_str

    async def validate_session(self, token_str: str) -> Session:
        """Validate JWT and return the Session record."""
        secret = self._get_secret()
        try:
            payload = jwt.decode(token_str, secret, algorithms=[settings.shade_jwt_algorithm])
        except JWTError:
            raise UnauthorizedError("Invalid or expired session token.")

        token_hash = _hash_token(token_str)
        result = await self._db.execute(
            select(Session).where(
                Session.token_hash == token_hash,
                Session.is_revoked == False,
            )
        )
        session = result.scalar_one_or_none()
        if session is None:
            raise UnauthorizedError("Session not found or revoked.")
        expires_at = session.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expires_at:
            raise UnauthorizedError("Session has expired.")
        return session

    async def revoke_session(self, session_id: str) -> None:
        session = await self._db.get(Session, session_id)
        if session:
            session.is_revoked = True
            session.revoked_at = datetime.now(timezone.utc)
            await self._db.flush()
