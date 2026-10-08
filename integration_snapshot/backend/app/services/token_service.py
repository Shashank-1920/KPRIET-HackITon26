"""
S.H.A.D.E. — Token Service
Role: Member 1 — Core Architecture + Backend + Database + Integration

Responsibilities:
  - Generate exactly 12-character cryptographically secure synthetic tokens.
  - Validate token format.
  - Check token collisions.
  - Reuse existing mapping for duplicate sensitive values (duplicate reuse invariant).
  - Create new mappings for new sensitive values.

TOKEN FORMAT: SHD_XXXXXXX
  - Prefix  : 'SHD_'   (4 chars, fixed)
  - Suffix  : 8 uppercase hex characters from secrets.token_hex(4) → 8 hex chars
  - Total   : 12 characters exactly
  - Safe    : Contains no recoverable information about the real sensitive value.

DUPLICATE REUSE RULE:
  If the same sensitive value (identified by lookup_hash) already has a token,
  return the existing token without creating a duplicate record.

CRYPTOGRAPHIC REQUIREMENT:
  Token generation uses secrets.token_hex() — Python's CSPRNG (urandom-backed).
  DO NOT use random.random() or any predictable source.
"""

import logging
import re
import secrets

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database.models import SensitiveValue, SyntheticToken

logger = logging.getLogger(__name__)

# Token regex: exactly SHD_ followed by 8 uppercase hex characters
_TOKEN_PATTERN = re.compile(r"^SHD_[0-9A-F]{8}$")
_TOKEN_PREFIX = "SHD_"
_MAX_COLLISION_RETRIES = 10


def generate_token() -> str:
    """
    Generate one 12-character cryptographically secure synthetic token.

    Format: SHD_ + 8 uppercase hex chars
    Uses secrets.token_hex for CSPRNG generation.
    """
    suffix = secrets.token_hex(4).upper()  # 4 random bytes → 8 hex chars
    token = _TOKEN_PREFIX + suffix
    assert len(token) == 12, f"Token length invariant violated: {len(token)}"
    return token


def validate_token_format(token: str) -> bool:
    """Return True iff the token matches the SHD_ format and is exactly 12 chars."""
    return bool(_TOKEN_PATTERN.match(token)) and len(token) == 12


class TokenService:
    """
    Service responsible for synthetic token lifecycle.
    All database operations go through this service — callers do not
    manipulate token records directly.
    """

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def get_or_create_token(
        self, sensitive_value: SensitiveValue
    ) -> SyntheticToken:
        """
        Return the existing SyntheticToken for this sensitive value if one exists,
        or generate a new collision-free token and persist it.

        Implements the duplicate reuse invariant:
          Same sensitive value → same token, no new record.
        """
        # Check for existing token (one-to-one relationship)
        stmt = select(SyntheticToken).where(
            SyntheticToken.sensitive_value_id == sensitive_value.id
        )
        result = await self._db.execute(stmt)
        existing = result.scalar_one_or_none()
        if existing is not None:
            logger.debug(
                "[TokenService] Reusing existing token %s for value_id=%s",
                existing.token, sensitive_value.id,
            )
            return existing

        # Generate a new collision-free token
        token_str = await self._generate_unique_token()
        token_record = SyntheticToken(
            sensitive_value_id=sensitive_value.id,
            token=token_str,
            data_type=sensitive_value.data_type,
        )
        self._db.add(token_record)
        await self._db.flush()  # get generated id without full commit
        logger.info(
            "[TokenService] Created new token %s for value_id=%s type=%s",
            token_str, sensitive_value.id, sensitive_value.data_type,
        )
        return token_record

    async def _generate_unique_token(self) -> str:
        """Generate a token that does not already exist in the database."""
        for attempt in range(_MAX_COLLISION_RETRIES):
            candidate = generate_token()
            stmt = select(SyntheticToken).where(SyntheticToken.token == candidate)
            result = await self._db.execute(stmt)
            if result.scalar_one_or_none() is None:
                return candidate
            logger.warning(
                "[TokenService] Token collision on attempt %d: %s", attempt + 1, candidate
            )
        raise RuntimeError(
            "[TokenService] Failed to generate unique token after "
            f"{_MAX_COLLISION_RETRIES} attempts. Token space exhaustion is unexpected."
        )

    async def lookup_by_token(self, token: str) -> SyntheticToken | None:
        """Return the SyntheticToken record for a given token string, or None."""
        if not validate_token_format(token):
            return None
        stmt = select(SyntheticToken).where(SyntheticToken.token == token)
        result = await self._db.execute(stmt)
        return result.scalar_one_or_none()

    async def token_exists(self, token: str) -> bool:
        """Return True if the token exists in the database."""
        return (await self.lookup_by_token(token)) is not None
