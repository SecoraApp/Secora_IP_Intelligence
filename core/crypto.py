"""
core/crypto.py — Column-level AES-256-GCM encryption for sensitive DB fields.

Key derivation:
    HKDF(SHA-256, ikm=SECRET_KEY, info=b'secora-db-encryption', length=32)

This means no new env var is needed — the key is derived from the existing
SECRET_KEY.  Rotating SECRET_KEY will make all encrypted values unreadable,
so treat SECRET_KEY rotation the same as a DB migration.

Usage:
    from core.crypto import encrypt, decrypt

    # Store
    user.totp_secret = encrypt(raw_secret)

    # Read
    raw_secret = decrypt(user.totp_secret)

Encrypted values are stored as base64url strings prefixed with 'enc:v1:'
so plain-text legacy values are still readable (decrypt() returns them as-is
if the prefix is absent).
"""

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_PREFIX = b'enc:v1:'
_KEY_CACHE: bytes | None = None


def _get_key() -> bytes:
    """Derive and cache the 32-byte AES key from SECRET_KEY."""
    global _KEY_CACHE
    if _KEY_CACHE is not None:
        return _KEY_CACHE

    from flask import current_app
    secret = current_app.config['SECRET_KEY']
    if isinstance(secret, str):
        secret = secret.encode()

    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b'secora-db-encryption',
    )
    _KEY_CACHE = hkdf.derive(secret)
    return _KEY_CACHE


def encrypt(plaintext: str | None) -> str | None:
    """
    Encrypt *plaintext* and return a base64url-encoded ciphertext string.
    Returns None if plaintext is None.
    Already-encrypted values (prefixed) are returned unchanged.
    """
    if plaintext is None:
        return None
    if isinstance(plaintext, bytes):
        plaintext = plaintext.decode()

    # Don't double-encrypt
    raw_bytes = plaintext.encode()
    if raw_bytes.startswith(_PREFIX):
        return plaintext

    nonce = os.urandom(12)  # 96-bit nonce for GCM
    aesgcm = AESGCM(_get_key())
    ciphertext = aesgcm.encrypt(nonce, raw_bytes, None)

    # Prefix + base64url(nonce + ciphertext)
    payload = base64.urlsafe_b64encode(_PREFIX + nonce + ciphertext)
    return payload.decode()


def decrypt(value: str | None) -> str | None:
    """
    Decrypt a value produced by encrypt().
    Returns the original string, or None if value is None.
    Values without the enc:v1: prefix are returned as-is (legacy plain text).
    """
    if value is None:
        return None

    try:
        raw = base64.urlsafe_b64decode(value.encode())
    except Exception:
        # Not base64 — legacy plain text
        return value

    if not raw.startswith(_PREFIX):
        # Legacy plain text stored without encryption
        return value

    payload = raw[len(_PREFIX):]
    nonce      = payload[:12]
    ciphertext = payload[12:]

    try:
        aesgcm    = AESGCM(_get_key())
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    except Exception:
        # Decryption failed — wrong key or corrupted data
        return None


def invalidate_key_cache() -> None:
    """Call this in tests or after SECRET_KEY rotation."""
    global _KEY_CACHE
    _KEY_CACHE = None