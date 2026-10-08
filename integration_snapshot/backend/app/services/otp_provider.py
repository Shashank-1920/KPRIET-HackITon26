"""
S.H.A.D.E. — Hardened OTP Provider Abstraction
Role: Member 1 — Core Architecture + Backend + Database + Integration

Provides OTP delivery, TTL expiry, attempt limiting, brute-force lockout,
and verified mobile registration tickets.

INVARIANTS:
- OTP expiry is 300 seconds.
- Maximum 3 verification attempts before lockout.
- Minimum 30 seconds cooldown between resends.
- OTP codes are hashed in memory — never stored plaintext.
- In production, OTP codes are NEVER logged and '000000' bypass is PROHIBITED.
- Mock provider is strictly rejected in production.
"""

import hashlib
import logging
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple

from backend.app.core.config import settings
from backend.app.core.crypto import compute_lookup_hash
from backend.app.core.errors import InvalidRequestError, UnauthorizedError

logger = logging.getLogger(__name__)

_OTP_TTL_SECONDS = 300
_OTP_COOLDOWN_SECONDS = 30
_MAX_VERIFY_ATTEMPTS = 3
_LOCKOUT_SECONDS = 300


@dataclass
class OTPEntry:
    code_hash: str
    created_at: datetime
    expires_at: datetime
    attempts_remaining: int
    locked_until: Optional[datetime] = None


# Storage keyed by lookup_hash of mobile number
_otp_store: Dict[str, OTPEntry] = {}
# Verified tickets: ticket_str -> (mobile_hash, verified_at, expires_at)
_verified_tickets: Dict[str, Tuple[str, datetime, datetime]] = {}


class OTPProvider(ABC):
    """Abstract base for OTP delivery providers."""

    @abstractmethod
    async def send_otp(self, mobile_number: str) -> bool:
        """Send an OTP to the given mobile number. Returns True on success."""

    @abstractmethod
    async def verify_otp(self, mobile_number: str, code: str) -> Tuple[bool, Optional[str]]:
        """
        Verify the OTP for the given mobile number.
        Returns (is_valid, verification_ticket).
        """

    def has_pending_otp(self, mobile_number: str) -> bool:
        """Check if an active, non-expired OTP is already pending."""
        phone_hash = compute_lookup_hash(mobile_number)
        entry = _otp_store.get(phone_hash)
        if entry is None:
            return False
        now = datetime.now(timezone.utc)
        if now > entry.expires_at:
            _otp_store.pop(phone_hash, None)
            return False
        return True


class BaseOTPProvider(OTPProvider):
    """Base logic for OTP hashing, verification, attempt tracking, and ticketing."""

    def _hash_code(self, mobile_number: str, code: str) -> str:
        salted = f"{mobile_number}:{code}"
        return hashlib.sha256(salted.encode("utf-8")).hexdigest()

    def _record_send(self, mobile_number: str, code: str) -> None:
        phone_hash = compute_lookup_hash(mobile_number)
        now = datetime.now(timezone.utc)
        entry = _otp_store.get(phone_hash)
        if entry and now < (entry.created_at + timedelta(seconds=_OTP_COOLDOWN_SECONDS)):
            raise InvalidRequestError("Please wait before requesting another OTP.")

        code_hash = self._hash_code(mobile_number, code)
        _otp_store[phone_hash] = OTPEntry(
            code_hash=code_hash,
            created_at=now,
            expires_at=now + timedelta(seconds=_OTP_TTL_SECONDS),
            attempts_remaining=_MAX_VERIFY_ATTEMPTS,
        )

    def _issue_verification_ticket(self, mobile_number: str) -> str:
        ticket = secrets.token_hex(32)
        now = datetime.now(timezone.utc)
        phone_hash = compute_lookup_hash(mobile_number)
        # Ticket valid for 15 minutes to complete device binding
        expires_at = now + timedelta(minutes=15)
        _verified_tickets[ticket] = (phone_hash, now, expires_at)
        return ticket

    def verify_ticket(self, ticket: str) -> str:
        """Validate ticket and return verified mobile_hash."""
        entry = _verified_tickets.get(ticket)
        if not entry:
            raise UnauthorizedError("Invalid or missing OTP verification ticket.")
        phone_hash, _, expires_at = entry
        now = datetime.now(timezone.utc)
        if now > expires_at:
            _verified_tickets.pop(ticket, None)
            raise UnauthorizedError("OTP verification ticket has expired. Please verify again.")
        # Single-use ticket
        _verified_tickets.pop(ticket, None)
        return phone_hash


class MockOTPProvider(BaseOTPProvider):
    """
    Development/test provider.
    Accepts 6-digit OTPs and '000000' in development mode.
    """

    async def send_otp(self, mobile_number: str) -> bool:
        if settings.shade_env == "production":
            raise InvalidRequestError("Mock OTP provider is not allowed in production.")

        code = str(secrets.randbelow(900000) + 100000)
        self._record_send(mobile_number, code)
        logger.info(
            "[MockOTP] DEV MODE OTP sent for %s...%s (code hidden for audit safety)",
            mobile_number[:3], mobile_number[-2:],
        )
        return True

    async def verify_otp(self, mobile_number: str, code: str) -> Tuple[bool, Optional[str]]:
        phone_hash = compute_lookup_hash(mobile_number)
        now = datetime.now(timezone.utc)

        # In dev mode only: '000000' bypass for tests
        if settings.shade_env != "production" and code == "000000":
            _otp_store.pop(phone_hash, None)
            ticket = self._issue_verification_ticket(mobile_number)
            return True, ticket

        entry = _otp_store.get(phone_hash)
        if entry is None:
            return False, None

        if entry.locked_until and now < entry.locked_until:
            raise UnauthorizedError("Too many failed attempts. Mobile verification locked.")

        if now > entry.expires_at:
            _otp_store.pop(phone_hash, None)
            return False, None

        expected_hash = self._hash_code(mobile_number, code)
        if secrets.compare_digest(entry.code_hash, expected_hash):
            _otp_store.pop(phone_hash, None)
            ticket = self._issue_verification_ticket(mobile_number)
            return True, ticket

        # Wrong code
        entry.attempts_remaining -= 1
        if entry.attempts_remaining <= 0:
            entry.locked_until = now + timedelta(seconds=_LOCKOUT_SECONDS)
            raise UnauthorizedError("Too many failed attempts. Account temporarily locked.")

        return False, None


class TwilioOTPProvider(BaseOTPProvider):
    """Production Twilio SMS provider stub."""

    async def send_otp(self, mobile_number: str) -> bool:
        logger.error("[TwilioOTP] Twilio not configured. Set TWILIO_* env vars.")
        return False

    async def verify_otp(self, mobile_number: str, code: str) -> Tuple[bool, Optional[str]]:
        return False, None


_otp_provider_instance: Optional[OTPProvider] = None


def get_otp_provider() -> OTPProvider:
    global _otp_provider_instance
    if _otp_provider_instance is None:
        provider_name = settings.otp_provider.lower()
        if provider_name == "twilio":
            _otp_provider_instance = TwilioOTPProvider()
        else:
            _otp_provider_instance = MockOTPProvider()
    return _otp_provider_instance
