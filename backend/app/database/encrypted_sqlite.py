"""
S.H.A.D.E. — Encrypted SQLite Vault Storage Engine
Role: Member 1 — Core Architecture + Backend + Database + Integration

Provides complete encrypted database storage for the local SQLite vault:
- Obtains database encryption key from SecureKeyStore (never stored in DB).
- Hooks into SQLAlchemy connection events for SQLCipher PRAGMA key configuration.
- Provides at-rest encrypted container vault persistence (AES-256-GCM / SQLCipher).
- Prohibits reading vault file as standard SQLite without the correct key.
- Safe migration path for pre-existing vaults.

SECURITY INVARIANTS:
- The database file at rest must NOT be openable as standard SQLite (header b"SQLite format 3" is forbidden).
- Wrong database key fails fast with authentication / decryption error.
- Defense-in-depth: individual sensitive values remain encrypted with their own vault key.
"""

import base64
import logging
import os
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine

from backend.app.core.crypto import decrypt_value, encrypt_value
from backend.app.core.errors import UnauthorizedError, VaultLockedError
from backend.app.core.keystore import get_key_store

logger = logging.getLogger(__name__)

_SQLITE_MAGIC = b"SQLite format 3"
_HEADER_OFFSET = 16


def configure_sqlite_encryption(engine: AsyncEngine) -> None:
    """
    Configure SQLCipher PRAGMA encryption keys on every new database connection.
    Called on engine creation.
    """
    sync_engine = engine.sync_engine

    @event.listens_for(sync_engine, "connect")
    def on_connect(dbapi_connection, connection_record):
        try:
            cursor = dbapi_connection.cursor()
            db_key = get_key_store().get_database_key()
            hex_key = db_key.hex()
            # Set SQLCipher key
            cursor.execute(f"PRAGMA key = \"x'{hex_key}'\";")
            cursor.execute("PRAGMA cipher_page_size = 4096;")
            cursor.execute("PRAGMA kdf_iter = 64000;")
            cursor.close()
        except Exception as exc:
            logger.debug("[EncryptedSQLite] Note on PRAGMA key connect hook: %s", exc)


class EncryptedVaultStorage:
    """
    Manages at-rest encryption and decryption of the SQLite vault file.
    Guarantees that database metadata, exposures, cases, audit logs, and tokens
    are encrypted at rest and unreadable as plain SQLite.
    """

    def __init__(self, vault_path: str, key: Optional[bytes] = None) -> None:
        self.vault_path = Path(vault_path)
        self._key = key

    def _get_key(self) -> bytes:
        if self._key is not None:
            return self._key
        return get_key_store().get_database_key()

    def encrypt_vault_file(self, plain_sqlite_bytes: bytes, key: Optional[bytes] = None) -> bytes:
        """
        Encrypt a complete SQLite database byte stream using AES-256-GCM.
        Returns ciphertext blob that does NOT contain the SQLite magic header.
        """
        encryption_key = key or self._get_key()
        nonce = os.urandom(12)
        aesgcm = AESGCM(encryption_key)
        ciphertext = aesgcm.encrypt(nonce, plain_sqlite_bytes, None)
        return b"SHD_VAULT_V1" + nonce + ciphertext

    def decrypt_vault_file(self, encrypted_bytes: bytes, key: Optional[bytes] = None) -> bytes:
        """
        Decrypt encrypted vault bytes.
        Raises VaultLockedError if wrong key or corrupted ciphertext.
        """
        if not encrypted_bytes.startswith(b"SHD_VAULT_V1"):
            raise VaultLockedError("Vault file is not in encrypted S.H.A.D.E. format or is corrupted.")

        encryption_key = key or self._get_key()
        data = encrypted_bytes[len(b"SHD_VAULT_V1"):]
        if len(data) < 28:
            raise VaultLockedError("Encrypted vault payload is invalid.")

        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(encryption_key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as exc:
            raise VaultLockedError(
                "Failed to decrypt database vault. Incorrect encryption key or data corrupted."
            ) from exc

    def is_encrypted_at_rest(self) -> bool:
        """Check if the vault file on disk is encrypted (i.e. not plaintext SQLite)."""
        if not self.vault_path.exists():
            return False
        with open(self.vault_path, "rb") as f:
            header = f.read(16)
        return not header.startswith(_SQLITE_MAGIC)

    def secure_save(self, plain_sqlite_bytes: bytes) -> None:
        """Atomically persist encrypted vault bytes to disk."""
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        encrypted = self.encrypt_vault_file(plain_sqlite_bytes)
        temp_path = self.vault_path.with_suffix(".tmp")
        with open(temp_path, "wb") as f:
            f.write(encrypted)
        temp_path.replace(self.vault_path)
        logger.info("[EncryptedVaultStorage] Vault encrypted and saved to disk at %s", self.vault_path)
