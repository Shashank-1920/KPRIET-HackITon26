"""
S.H.A.D.E. — Authentication Provider Abstraction (Biometric & PIN)
Role: Member 1 — Core Architecture + Backend + Database + Integration

Enforces challenge-response authentication for owner authorization:
- Client cannot simply claim "auth_method": "BIOMETRIC" or "PIN"
- Backend issues a time-bound cryptographic challenge nonce
- Backend consumes a verified authentication assertion
- Biometric verification consumes cryptographic platform assertions
- PIN verification uses Argon2id with rate limiting and lockout
- Raw biometrics are NEVER accepted or stored
- Plaintext PINs are NEVER logged or stored
"""

import logging
import secrets
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from backend.app.core.config import settings
from backend.app.core.errors import UnauthorizedError
from backend.app.database.models import Owner

logger = logging.getLogger(__name__)

_ph = PasswordHasher()
_MAX_PIN_ATTEMPTS = 3
_LOCKOUT_SECONDS = 300
_CHALLENGE_TTL_SECONDS = 60


@dataclass
class AuthChallenge:
    challenge_id: str
    owner_id: str
    action: str
    resource_id: str
    nonce: str
    created_at: datetime
    expires_at: datetime
    consumed: bool = False


class AuthenticationProvider(ABC):
    """Abstract interface for local device owner authentication."""

    @abstractmethod
    def create_challenge(self, owner_id: str, action: str, resource_id: str) -> AuthChallenge:
        """Create a single-use time-bound challenge for an authorization decision."""

    @abstractmethod
    def verify_biometric_assertion(
        self,
        challenge_id: str,
        assertion: Any,
        owner_id: Optional[str] = None,
    ) -> bool:
        """Verify a platform-signed biometric assertion against an active challenge."""

    @abstractmethod
    def verify_pin_assertion(
        self,
        owner: Owner,
        pin_input: str,
        challenge_id: Optional[str] = None,
    ) -> bool:
        """Verify device PIN fallback assertion with Argon2id and rate-limiting."""


class BaseAuthProvider(AuthenticationProvider):
    """Shared state management for challenges and PIN attempts."""

    def __init__(self) -> None:
        self._challenges: Dict[str, AuthChallenge] = {}
        self._pin_attempts: Dict[str, int] = {}
        self._pin_lockouts: Dict[str, datetime] = {}

    def create_challenge(self, owner_id: str, action: str, resource_id: str) -> AuthChallenge:
        now = datetime.now(timezone.utc)
        challenge = AuthChallenge(
            challenge_id=str(uuid.uuid4()),
            owner_id=owner_id,
            action=action,
            resource_id=resource_id,
            nonce=secrets.token_hex(16),
            created_at=now,
            expires_at=now + timedelta(seconds=_CHALLENGE_TTL_SECONDS),
        )
        self._challenges[challenge.challenge_id] = challenge
        logger.info(
            "[AuthProvider] Created challenge id=%s for owner=%s action=%s",
            challenge.challenge_id, owner_id, action,
        )
        return challenge

    def _validate_and_consume_challenge(
        self, challenge_id: str, expected_owner_id: Optional[str] = None
    ) -> AuthChallenge:
        challenge = self._challenges.get(challenge_id)
        if challenge is None:
            raise UnauthorizedError("Invalid or unknown authentication challenge.")
        if challenge.consumed:
            raise UnauthorizedError("Authentication challenge has already been used.")
        now = datetime.now(timezone.utc)
        if now > challenge.expires_at:
            raise UnauthorizedError("Authentication challenge has expired.")
        if expected_owner_id and challenge.owner_id != expected_owner_id:
            raise UnauthorizedError("Challenge does not match authenticated owner.")

        challenge.consumed = True
        return challenge

    def _check_pin_rate_limit(self, owner_id: str) -> None:
        now = datetime.now(timezone.utc)
        lockout = self._pin_lockouts.get(owner_id)
        if lockout and now < lockout:
            remaining = int((lockout - now).total_seconds())
            raise UnauthorizedError(
                f"Too many failed PIN attempts. Locked out for {remaining} seconds."
            )

    def _record_pin_failure(self, owner_id: str) -> None:
        attempts = self._pin_attempts.get(owner_id, 0) + 1
        self._pin_attempts[owner_id] = attempts
        logger.warning("[AuthProvider] Failed PIN attempt %d/%d for owner=%s", attempts, _MAX_PIN_ATTEMPTS, owner_id)
        if attempts >= _MAX_PIN_ATTEMPTS:
            lockout_until = datetime.now(timezone.utc) + timedelta(seconds=_LOCKOUT_SECONDS)
            self._pin_lockouts[owner_id] = lockout_until
            self._pin_attempts[owner_id] = 0
            logger.warning("[AuthProvider] Owner %s locked out until %s", owner_id, lockout_until)

    def _record_pin_success(self, owner_id: str) -> None:
        self._pin_attempts.pop(owner_id, None)
        self._pin_lockouts.pop(owner_id, None)


class DevAuthenticationProvider(BaseAuthProvider):
    """
    Development/CI authentication provider.
    Explicitly marked DEV ONLY.
    Supports development mock biometric assertions and Argon2id PIN verification.
    """

    def verify_biometric_assertion(
        self,
        challenge_id: str,
        assertion: Any,
        owner_id: Optional[str] = None,
    ) -> bool:
        if settings.shade_env == "production":
            logger.error("[AuthProvider] Dev provider invoked in PRODUCTION! Rejecting.")
            return False

        challenge = self._validate_and_consume_challenge(challenge_id, owner_id)
        # Development assertion check
        if isinstance(assertion, dict):
            # Must reference the same challenge_id and contain a non-empty assertion signature/token
            if assertion.get("challenge_id") != challenge.challenge_id:
                return False
            if assertion.get("verified") is True or assertion.get("signature"):
                return True
        elif isinstance(assertion, str) and assertion in ("dev-biometric-assertion-valid", "BIOMETRIC_PASS"):
            return True

        return False

    def verify_pin_assertion(
        self,
        owner: Owner,
        pin_input: str,
        challenge_id: Optional[str] = None,
    ) -> bool:
        if challenge_id:
            self._validate_and_consume_challenge(challenge_id, owner.id)

        self._check_pin_rate_limit(owner.id)

        if not owner.pin_hash:
            logger.warning("[AuthProvider] Owner %s has no configured PIN.", owner.id)
            return False

        try:
            _ph.verify(owner.pin_hash, pin_input)
            self._record_pin_success(owner.id)
            return True
        except VerifyMismatchError:
            self._record_pin_failure(owner.id)
            return False
        except Exception as exc:
            logger.error("[AuthProvider] PIN verification error: %s", type(exc).__name__)
            return False


class PlatformBiometricProvider(BaseAuthProvider):
    """
    Platform biometric provider supporting hardware authenticators (Windows Hello / WebAuthn / TPM).
    Verifies cryptographic assertions signed by the device's hardware key pair over the challenge nonce.
    Rejects mock flags, strings, client-forged authentication claims, and replay attempts.
    """

    def __init__(self) -> None:
        super().__init__()
        # In-memory registered platform credentials: {owner_id: {credential_id: {"key": pub_key, "type": "ed25519"|"p256"}}}
        self._registered_credentials: Dict[str, Dict[str, Dict[str, Any]]] = {}

    def register_credential(
        self,
        owner_id: str,
        credential_id: str,
        public_key_bytes: bytes,
        key_type: str = "ed25519",
    ) -> None:
        """Register a hardware authenticator public key bound to the owner."""
        if owner_id not in self._registered_credentials:
            self._registered_credentials[owner_id] = {}
        self._registered_credentials[owner_id][credential_id] = {
            "public_key_bytes": public_key_bytes,
            "key_type": key_type.lower(),
        }
        logger.info("[PlatformBiometric] Registered credential %s for owner %s", credential_id, owner_id)

    def check_platform_hardware_status(self) -> Dict[str, Any]:
        """
        Truthfully inspects the local host for platform biometric hardware availability.
        """
        import platform
        os_name = platform.system()
        is_windows = os_name == "Windows"
        webauthn_dll_available = False

        if is_windows:
            try:
                import ctypes
                ctypes.windll.LoadLibrary("webauthn.dll")
                webauthn_dll_available = True
            except Exception:
                webauthn_dll_available = False

        return {
            "platform": os_name,
            "hardware_biometric_supported": is_windows and webauthn_dll_available,
            "provider_name": "Windows Hello / WebAuthn Native Platform Provider" if is_windows else "FIDO2 Platform Provider",
            "requires_physical_user_presence": True,
            "verification_algorithm": "Ed25519 / ECDSA-P256-SHA256",
        }

    def verify_biometric_assertion(
        self,
        challenge_id: str,
        assertion: Any,
        owner_id: Optional[str] = None,
    ) -> bool:
        """
        Verify a platform cryptographic assertion:
        - Challenge is validated and consumed (anti-replay).
        - Must contain signature, challenge nonce, and user_verified flag.
        - Cryptographic signature verified against registered public key.
        - Rejects unverified client flags, mock strings, or unauthenticated payloads.
        """
        challenge = self._validate_and_consume_challenge(challenge_id, owner_id)

        if not isinstance(assertion, dict):
            logger.warning("[PlatformBiometric] Assertion rejected: not a valid dictionary payload.")
            return False

        # Reject client-supplied forgery flags like {"verified": true} without signature
        signature_raw = assertion.get("signature")
        client_nonce = assertion.get("nonce")
        user_verified = assertion.get("user_verified")

        if not signature_raw or not client_nonce:
            logger.warning("[PlatformBiometric] Missing cryptographic signature or nonce in assertion.")
            return False

        if client_nonce != challenge.nonce:
            logger.warning("[PlatformBiometric] Nonce mismatch: client %s != challenge %s", client_nonce, challenge.nonce)
            return False

        if user_verified is not True:
            logger.warning("[PlatformBiometric] User verification (UV) flag not asserted by platform.")
            return False

        credential_id = assertion.get("credential_id", "default")
        owner_creds = self._registered_credentials.get(challenge.owner_id, {})
        cred_info = owner_creds.get(credential_id)

        if not cred_info:
            logger.warning("[PlatformBiometric] No registered credential %s for owner %s", credential_id, challenge.owner_id)
            return False

        # Verify signature
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec, ed25519

            if isinstance(signature_raw, str):
                try:
                    sig_bytes = bytes.fromhex(signature_raw)
                except ValueError:
                    import base64
                    sig_bytes = base64.b64decode(signature_raw)
            else:
                sig_bytes = bytes(signature_raw)

            nonce_bytes = challenge.nonce.encode("utf-8")
            pub_bytes = cred_info["public_key_bytes"]
            key_type = cred_info["key_type"]

            if key_type == "ed25519":
                pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
                pub_key.verify(sig_bytes, nonce_bytes)
                logger.info("[PlatformBiometric] Ed25519 signature verified for owner %s", challenge.owner_id)
                return True
            elif key_type in ("p256", "ecdsa"):
                from cryptography.hazmat.primitives.serialization import load_der_public_key, load_pem_public_key
                try:
                    pub_key = load_der_public_key(pub_bytes)
                except Exception:
                    pub_key = load_pem_public_key(pub_bytes)
                pub_key.verify(sig_bytes, nonce_bytes, ec.ECDSA(hashes.SHA256()))
                logger.info("[PlatformBiometric] ECDSA-P256 signature verified for owner %s", challenge.owner_id)
                return True
            else:
                logger.error("[PlatformBiometric] Unsupported key type: %s", key_type)
                return False
        except Exception as exc:
            logger.warning("[PlatformBiometric] Cryptographic verification failed: %s", exc)
            return False

    def verify_pin_assertion(
        self,
        owner: Owner,
        pin_input: str,
        challenge_id: Optional[str] = None,
    ) -> bool:
        if challenge_id:
            self._validate_and_consume_challenge(challenge_id, owner.id)

        self._check_pin_rate_limit(owner.id)

        if not owner.pin_hash:
            logger.warning("[PlatformBiometric] Owner %s has no configured PIN.", owner.id)
            return False

        try:
            _ph.verify(owner.pin_hash, pin_input)
            self._record_pin_success(owner.id)
            return True
        except VerifyMismatchError:
            self._record_pin_failure(owner.id)
            return False
        except Exception:
            return False


class ProductionAuthenticationProvider(PlatformBiometricProvider):
    """
    Production authentication provider aliases to PlatformBiometricProvider.
    Enforces hardware/platform cryptographic assertion verification.
    """
    pass


_auth_provider_instance: Optional[AuthenticationProvider] = None


def get_auth_provider() -> AuthenticationProvider:
    global _auth_provider_instance
    if _auth_provider_instance is None:
        if settings.shade_env == "production":
            _auth_provider_instance = ProductionAuthenticationProvider()
        else:
            _auth_provider_instance = DevAuthenticationProvider()
    return _auth_provider_instance

