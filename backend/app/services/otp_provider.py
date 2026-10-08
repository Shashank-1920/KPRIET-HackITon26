"""
S.H.A.D.E. — OTP Provider Abstraction
Role: Member 1 — Core Architecture + Backend + Database + Integration

Provides a clean provider abstraction for OTP delivery.
DO NOT commit real credentials. This file defines the interface only.

Providers:
  - MockOTPProvider  : Development/test — logs OTP to console, always verifies "000000"
  - TwilioOTPProvider: (stub) — configure TWILIO_* env vars when available
  - Fast2SMSProvider : (stub) — configure FAST2SMS_* env vars when available

The active provider is selected by OTP_PROVIDER env variable.
"""

import logging
import secrets
from abc import ABC, abstractmethod
from typing import Optional

from backend.app.core.config import settings

logger = logging.getLogger(__name__)

# In-memory OTP store for development (no persistence, single-device only)
# Production should use a short-lived DB or in-memory store with TTL.
_otp_store: dict[str, str] = {}  # mobile_hash → OTP code


class OTPProvider(ABC):
    """Abstract base for OTP delivery providers."""

    @abstractmethod
    async def send_otp(self, mobile_number: str) -> bool:
        """Send an OTP to the given mobile number. Returns True on success."""

    @abstractmethod
    async def verify_otp(self, mobile_number: str, code: str) -> bool:
        """Verify the OTP for the given mobile number. Returns True if valid."""

    def has_pending_otp(self, mobile_number: str) -> bool:
        """Check if an OTP is already pending for this mobile number."""
        return False


class MockOTPProvider(OTPProvider):
    """
    Development/test provider.
    Generates a 6-digit OTP, logs it (NOT for production!), and accepts it.
    In tests, the code "000000" is always valid.
    """

    def has_pending_otp(self, mobile_number: str) -> bool:
        return mobile_number in _otp_store

    async def send_otp(self, mobile_number: str) -> bool:
        code = secrets.randbelow(900000) + 100000  # 6-digit, 100000–999999
        otp_code = str(code)
        _otp_store[mobile_number] = otp_code
        # WARNING: In production, never log OTPs. This is dev-only.
        logger.warning(
            "[MockOTP] DEV MODE — OTP for %s...%s: %s",
            mobile_number[:3], mobile_number[-2:], otp_code,
        )
        return True

    async def verify_otp(self, mobile_number: str, code: str) -> bool:
        # Test convenience: "000000" always works in mock mode
        if code == "000000":
            _otp_store.pop(mobile_number, None)
            return True
        stored = _otp_store.get(mobile_number)
        if stored and stored == code:
            del _otp_store[mobile_number]  # OTP is single-use
            return True
        return False


class TwilioOTPProvider(OTPProvider):
    """
    Twilio SMS provider stub.
    Configure TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER in .env.
    This stub must not be activated without proper credentials.
    """

    async def send_otp(self, mobile_number: str) -> bool:
        logger.error("[TwilioOTP] Twilio not configured. Set TWILIO_* env vars.")
        return False

    async def verify_otp(self, mobile_number: str, code: str) -> bool:
        return False


def get_otp_provider() -> OTPProvider:
    """Return the active OTP provider based on OTP_PROVIDER env var."""
    provider_name = settings.otp_provider.lower()
    if provider_name == "twilio":
        return TwilioOTPProvider()
    # Default: mock provider for dev/test
    return MockOTPProvider()
