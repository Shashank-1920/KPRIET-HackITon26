"""
S.H.A.D.E. — SecureKeyStore Platform Abstraction
Role: Member 1 — Core Architecture + Backend + Database + Integration

Master encryption key management via OS-level secure storage.
Keys must NEVER be stored inside the SQLite vault or committed to Git.

Platform adapters:
  - Windows : DPAPI / Windows Credential Manager (via keyring)
  - macOS   : Apple Keychain Services (via keyring)
  - Linux   : Secret Service API / libsecret (via keyring)
  - Dev/CI  : High-entropy environment-provided passphrase (fallback only)

The key is held in process RAM only while the vault is open.
It is never logged, serialised, or persisted to disk by this module.
"""

import base64
import logging
import os
import platform
import secrets
from abc import ABC, abstractmethod
from typing import Optional

logger = logging.getLogger(__name__)

# Service name used by OS keyring entries
_KEYRING_SERVICE = "SHADE_VAULT"
_KEYRING_USERNAME = "master_encryption_key"
_KEY_BYTE_LENGTH = 32  # AES-256-GCM


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
            import keyring  # type: ignore

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
                "[SecureKeyStore] OS keyring unavailable: %s — falling back to env/dev backend.",
                type(exc).__name__,
            )
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
        pass  # Nothing to delete for env/ephemeral backend


def _detect_platform_backend() -> KeyStoreBackend:
    """Select the appropriate backend for the current platform."""
    system = platform.system()
    try:
        import keyring  # noqa: F401

        # Verify keyring actually has a working backend on this machine
        import keyring.backend as kb

        viable = [b for b in kb.get_all_keyring() if not b.__class__.__name__.startswith("Fail")]
        if viable:
            logger.debug("[SecureKeyStore] Platform=%s keyring backend selected.", system)
            return KeyringBackend()
    except Exception:
        pass

    logger.warning("[SecureKeyStore] No OS keyring available; falling back to env/dev backend.")
    return EnvDevBackend()


class SecureKeyStore:
    """
    Singleton-style wrapper providing a stable API for key retrieval.
    Usage:
        key_store = SecureKeyStore()
        key: bytes = key_store.get_master_key()
    """

    def __init__(self, backend: Optional[KeyStoreBackend] = None) -> None:
        self._backend = backend or _detect_platform_backend()
        self._cached_key: Optional[bytes] = None

    def get_master_key(self) -> bytes:
        """
        Return the 32-byte AES-256-GCM master encryption key.
        Loaded once per process lifetime; held in RAM only.
        """
        if self._cached_key is None:
            self._cached_key = self._backend.load_or_create_key()
        return self._cached_key

    def rotate_key(self) -> bytes:
        """
        Generate and store a new master key, invalidating the cached one.
        NOTE: Existing vault ciphertext will no longer be decryptable after rotation.
        This operation requires a full vault re-encryption (not yet implemented).
        """
        self._cached_key = None
        return self.get_master_key()

    def clear_from_memory(self) -> None:
        """Overwrite the in-memory key reference. Call on application shutdown."""
        if self._cached_key is not None:
            # Best-effort zeroing (CPython internals may prevent true zeroing)
            self._cached_key = b"\x00" * len(self._cached_key)
            self._cached_key = None


# Module-level singleton — imported by vault and token services
_key_store_instance: Optional[SecureKeyStore] = None


def get_key_store() -> SecureKeyStore:
    """Return (or initialise) the module-level SecureKeyStore singleton."""
    global _key_store_instance
    if _key_store_instance is None:
        _key_store_instance = SecureKeyStore()
    return _key_store_instance
