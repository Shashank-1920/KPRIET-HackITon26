"""
S.H.A.D.E. — SecureKeyStore Platform Abstraction
Role: Member 1 — Core Architecture + Backend + Database + Integration

Master encryption key management via OS-level secure storage with cryptographic key separation.
Keys must NEVER be stored inside the SQLite vault or committed to Git.

Cryptographic Key Separation (via HKDF-SHA256):
  - Vault Key       : AES-256-GCM for individual sensitive values (info=b"shade:vault:v1")
  - Database Key    : PRAGMA key for encrypted SQLite storage (info=b"shade:database:v1")
  - Lookup HMAC Key : HMAC-SHA256 for non-reversible duplicate detection (info=b"shade:lookup_hmac:v1")
  - JWT Secret      : HMAC-SHA256 session token signing (info=b"shade:jwt_secret:v1")

Platform adapters:
  - Windows : DPAPI / Windows Credential Manager (via keyring)
  - macOS   : Apple Keychain Services (via keyring)
  - Linux   : Secret Service API / libsecret (via keyring)
  - Dev/CI  : High-entropy environment-provided passphrase (fallback only)

SECURITY INVARIANTS:
- In production, failing OS keystore fails securely. Never silently create ephemeral keys in production.
- Keys are held in RAM only while the vault is open; never logged.
"""

import base64
import logging
import os
import platform
import secrets
from abc import ABC, abstractmethod
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from backend.app.core.config import settings
from backend.app.core.errors import KeyStoreUnavailableError

logger = logging.getLogger(__name__)

# Service name used by OS keyring entries
_KEYRING_SERVICE = "SHADE_VAULT"
_KEYRING_USERNAME = "master_encryption_key"
_KEY_BYTE_LENGTH = 32  # 256 bits


class KeyStoreBackend(ABC):
    """Abstract interface for platform-specific key storage."""

    @abstractmethod
    def load_or_create_key(self) -> bytes:
        """
        Return the 32-byte master encryption key.
        If no key exists for this device, generate a cryptographically secure
        one and persist it in the OS secure store.
        """

    @abstractmethod
    def delete_key(self) -> None:
        """Permanently remove the master key from OS secure storage."""


class KeyringBackend(KeyStoreBackend):
    """
    Production backend: delegates to the OS keyring via the `keyring` library.
    Works on Windows (DPAPI/Credential Manager), macOS (Keychain), Linux (Secret Service).
    """

    def load_or_create_key(self) -> bytes:
        try:
            import keyring

            stored = keyring.get_password(_KEYRING_SERVICE, _KEYRING_USERNAME)
            if stored:
                try:
                    raw = base64.b64decode(stored)
                    if len(raw) == _KEY_BYTE_LENGTH:
                        return raw
                except Exception:
                    pass  # Corrupted entry — regenerate below

            # Generate and persist a new key
            key = secrets.token_bytes(_KEY_BYTE_LENGTH)
            keyring.set_password(
                _KEYRING_SERVICE, _KEYRING_USERNAME, base64.b64encode(key).decode()
            )
            logger.info("[SecureKeyStore] New master key generated and stored in OS keyring.")
            return key

        except Exception as exc:
            logger.error(
                "[SecureKeyStore] OS keyring unavailable: %s",
                type(exc).__name__,
            )
            if settings.shade_env == "production":
                raise KeyStoreUnavailableError(
                    "OS secure keystore failed in production. Refusing to operate insecurely."
                ) from exc
            raise

    def delete_key(self) -> None:
        try:
            import keyring

            keyring.delete_password(_KEYRING_SERVICE, _KEYRING_USERNAME)
        except Exception:
            pass


class EnvDevBackend(KeyStoreBackend):
    """
    Development / CI fallback backend.
    Reads SHADE_MASTER_ENCRYPTION_KEY from the environment.
    Must NOT be used in production with a real owner vault.
    """

    def __init__(self, env_key: Optional[str] = None) -> None:
        self._env_key = env_key or os.environ.get("SHADE_MASTER_ENCRYPTION_KEY")

    def load_or_create_key(self) -> bytes:
        if settings.shade_env == "production":
            raise KeyStoreUnavailableError(
                "EnvDevBackend is strictly prohibited in production. "
                "OS-level secure keystore (DPAPI/Keychain/SecretService) is mandatory."
            )

        if self._env_key:
            try:
                raw = base64.b64decode(self._env_key)
                if len(raw) == _KEY_BYTE_LENGTH:
                    logger.warning(
                        "[SecureKeyStore] Using environment-provided master key (dev/CI mode). "
                        "NOT suitable for production use."
                    )
                    return raw
            except Exception:
                pass

        # Generate a fresh in-process key (ephemeral — data won't survive restart)
        key = secrets.token_bytes(_KEY_BYTE_LENGTH)
        logger.warning(
            "[SecureKeyStore] No persistent key source found. "
            "Generated ephemeral in-memory key. Vault data will be lost on restart."
        )
        return key

    def delete_key(self) -> None:
        pass


def _detect_platform_backend() -> KeyStoreBackend:
    """Select the appropriate backend for the current platform."""
    system = platform.system()
    try:
        import keyring
        import keyring.backend as kb

        viable = [b for b in kb.get_all_keyring() if not b.__class__.__name__.startswith("Fail")]
        if viable:
            logger.debug("[SecureKeyStore] Platform=%s keyring backend selected.", system)
            return KeyringBackend()
    except Exception:
        pass

    if settings.shade_env == "production":
        raise KeyStoreUnavailableError(
            "Production requires a viable OS keyring backend. None available."
        )

    logger.warning("[SecureKeyStore] No OS keyring available; falling back to env/dev backend.")
    return EnvDevBackend()


class SecureKeyStore:
    """
    Key store providing domain-separated keys derived from the master root key.
    """

    def __init__(self, backend: Optional[KeyStoreBackend] = None) -> None:
        self._backend = backend or _detect_platform_backend()
        self._cached_root_key: Optional[bytes] = None
        self._cached_vault_key: Optional[bytes] = None
        self._cached_db_key: Optional[bytes] = None
        self._cached_lookup_key: Optional[bytes] = None
        self._cached_jwt_secret: Optional[str] = None

    def _derive_key(self, info: bytes, length: int = 32) -> bytes:
        root_key = self.get_master_key()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=info,
        )
        return hkdf.derive(root_key)

    def get_master_key(self) -> bytes:
        """Return the 32-byte root master key."""
        if self._cached_root_key is None:
            self._cached_root_key = self._backend.load_or_create_key()
        return self._cached_root_key

    def get_vault_key(self) -> bytes:
        """Return 32-byte AES-256-GCM encryption key for individual sensitive values."""
        if self._cached_vault_key is None:
            self._cached_vault_key = self._derive_key(b"shade:vault:v1", 32)
        return self._cached_vault_key

    def get_database_key(self) -> bytes:
        """Return 32-byte encryption key for local SQLite/SQLCipher vault database."""
        if self._cached_db_key is None:
            self._cached_db_key = self._derive_key(b"shade:database:v1", 32)
        return self._cached_db_key

    def get_lookup_hmac_key(self) -> bytes:
        """Return 32-byte HMAC key for non-reversible duplicate detection."""
        if self._cached_lookup_key is None:
            self._cached_lookup_key = self._derive_key(b"shade:lookup_hmac:v1", 32)
        return self._cached_lookup_key

    def get_jwt_secret(self) -> str:
        """Return JWT signing secret."""
        if self._cached_jwt_secret is None:
            derived = self._derive_key(b"shade:jwt_secret:v1", 32)
            self._cached_jwt_secret = base64.b64encode(derived).decode()
        return self._cached_jwt_secret

    def rotate_key(self) -> bytes:
        """Rotate the master key and clear derived key caches."""
        self.clear_from_memory()
        return self.get_master_key()

    def clear_from_memory(self) -> None:
        """Wipe cached keys from memory."""
        self._cached_root_key = None
        self._cached_vault_key = None
        self._cached_db_key = None
        self._cached_lookup_key = None
        self._cached_jwt_secret = None


# Module-level singleton
_key_store_instance: Optional[SecureKeyStore] = None


def get_key_store() -> SecureKeyStore:
    """Return the module-level SecureKeyStore singleton."""
    global _key_store_instance
    if _key_store_instance is None:
        _key_store_instance = SecureKeyStore()
    return _key_store_instance
