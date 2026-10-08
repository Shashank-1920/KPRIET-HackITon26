"""
S.H.A.D.E. — AES-256-GCM Vault Encryption Primitives
Role: Member 1 — Core Architecture + Backend + Database + Integration

Provides low-level encrypt/decrypt operations for the local vault.
- Algorithm : AES-256-GCM (authenticated encryption)
- Nonce     : 12-byte random, unique per encryption call
- Tag       : 16-byte GCM authentication tag (appended to ciphertext)
- Key       : 32-byte key from SecureKeyStore (never from DB)

Output format:  nonce (12 bytes) | ciphertext | tag (16 bytes)
All stored as raw bytes in the database BLOB column.

SECURITY INVARIANTS:
- Never log the plaintext or the key.
- Never reuse a nonce with the same key.
- Decryption failures raise an exception; callers must handle them.
"""

import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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


def compute_lookup_hash(value: str) -> str:
    """
    Compute a secure SHA-256 hex digest of a sensitive value.

    Used to detect duplicate sensitive values without storing plaintext.
    The hash allows equality checks in the database while keeping the
    original value protected behind encryption.

    IMPORTANT: This is a one-way function. The hash MUST NOT be used to
    reconstruct the original value.
    """
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()
