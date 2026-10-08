"""
S.H.A.D.E. — AES-256-GCM Vault Encryption Primitives & Keyed Lookup
Role: Member 1 — Core Architecture + Backend + Database + Integration

Provides low-level encrypt/decrypt operations and keyed lookup hashing.
- Algorithm : AES-256-GCM (authenticated encryption)
- Nonce     : 12-byte random, unique per encryption call
- Tag       : 16-byte GCM authentication tag (appended to ciphertext)
- Key       : 32-byte key from SecureKeyStore (never from DB)
- Lookup    : Keyed HMAC-SHA256 with dedicated lookup key (resists offline rainbow tables)

Output format:  nonce (12 bytes) | ciphertext | tag (16 bytes)
All stored as raw bytes in the database BLOB column.

SECURITY INVARIANTS:
- Never log the plaintext or the key.
- Never reuse a nonce with the same key.
- Decryption failures raise an exception; callers must handle them.
- Lookup hash is deterministic for duplicate detection, but keyed to prevent dictionary attacks.
"""

import hashlib
import hmac
import secrets
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.app.core.keystore import get_key_store

_NONCE_SIZE = 12  # bytes — GCM standard


def encrypt_value(plaintext: str, key: bytes) -> bytes:
    """
    Encrypt a UTF-8 string with AES-256-GCM.

    Returns:
        bytes: nonce (12) || ciphertext || tag (16) — ready for BLOB storage.

    Raises:
        ValueError: if the key is not exactly 32 bytes.
    """
    if len(key) != 32:
        raise ValueError("Master encryption key must be exactly 32 bytes.")
    nonce = secrets.token_bytes(_NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce + ciphertext_with_tag


def decrypt_value(blob: bytes, key: bytes) -> str:
    """
    Decrypt an AES-256-GCM BLOB produced by :func:`encrypt_value`.

    Returns:
        str: The original UTF-8 plaintext.

    Raises:
        ValueError : key length mismatch.
        cryptography.exceptions.InvalidTag : authentication failed (tampered/wrong key).
    """
    if len(key) != 32:
        raise ValueError("Master encryption key must be exactly 32 bytes.")
    if len(blob) < _NONCE_SIZE + 16:
        raise ValueError("Encrypted blob is too short to be valid.")
    nonce = blob[:_NONCE_SIZE]
    ciphertext_with_tag = blob[_NONCE_SIZE:]
    aesgcm = AESGCM(key)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    return plaintext_bytes.decode("utf-8")


def compute_lookup_hash(value: str, key: Optional[bytes] = None) -> str:
    """
    Compute a keyed HMAC-SHA256 hex digest of a sensitive value.

    Used to detect duplicate sensitive values without storing plaintext.
    Uses a dedicated LOOKUP_HMAC_KEY separate from the vault AES key and JWT secret.
    The keyed hash prevents offline rainbow-table and dictionary preimage attacks.

    IMPORTANT: This is a one-way function. The hash MUST NOT be used to
    reconstruct the original value.
    """
    lookup_key = key if key is not None else get_key_store().get_lookup_hmac_key()
    return hmac.new(lookup_key, value.encode("utf-8"), hashlib.sha256).hexdigest()
