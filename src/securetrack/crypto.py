"""Authenticated encryption primitives used by SecureTrack.

The prototype uses AES-256 in Galois/Counter Mode (GCM) for authenticated
encryption and Scrypt to derive a 256-bit key from a user passphrase.

Design notes
------------
* AES-GCM provides confidentiality *and* integrity in a single primitive,
  which means tampering with any byte of the ciphertext (or the salt /
  nonce / metadata used as associated data) causes decryption to fail.
* Scrypt is a memory-hard KDF and is resistant to GPU/ASIC attacks. The
  parameters below follow the OWASP cheat sheet (n=2**15, r=8, p=1) and
  are deliberately conservative for a desktop application.
* Salts are 16 bytes and nonces are 12 bytes, both drawn from
  :func:`os.urandom` via the helper functions in this module.

All functions raise :class:`InvalidPassphraseError` for any failure to
authenticate, regardless of the underlying cause, so a caller cannot
distinguish a wrong passphrase from a tampered package.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# --- public constants -------------------------------------------------------

ALGORITHM_NAME: str = "AES-256-GCM"
KDF_NAME: str = "scrypt"

#: Length of the AES-256 key in bytes.
KEY_LENGTH: int = 32
#: Length of the Scrypt salt in bytes.
SALT_LENGTH: int = 16
#: Length of the AES-GCM nonce in bytes (96 bits is the GCM standard).
NONCE_LENGTH: int = 12

#: Scrypt cost parameters. Tuned for a desktop application: roughly
#: ~30 MB of memory and a few hundred milliseconds on a modern laptop.
SCRYPT_N: int = 2**15
SCRYPT_R: int = 8
SCRYPT_P: int = 1


class InvalidPassphraseError(Exception):
    """Raised when decryption fails (wrong passphrase or tampered package)."""


@dataclass(frozen=True)
class EncryptionResult:
    """Output of a successful encryption operation."""

    ciphertext: bytes
    salt: bytes
    nonce: bytes


# --- helpers ---------------------------------------------------------------


def generate_salt() -> bytes:
    """Return a fresh cryptographically secure salt."""
    return os.urandom(SALT_LENGTH)


def generate_nonce() -> bytes:
    """Return a fresh cryptographically secure 96-bit nonce."""
    return os.urandom(NONCE_LENGTH)


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from the given passphrase and salt.

    Args:
        passphrase: User-supplied passphrase. Must be non-empty.
        salt: Salt of length :data:`SALT_LENGTH`.

    Returns:
        A 32-byte AES key.
    """
    if not passphrase:
        raise ValueError("passphrase must not be empty")
    if len(salt) != SALT_LENGTH:
        raise ValueError(f"salt must be {SALT_LENGTH} bytes, got {len(salt)}")

    kdf = Scrypt(
        salt=salt,
        length=KEY_LENGTH,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    return kdf.derive(passphrase.encode("utf-8"))


# --- core encryption / decryption ------------------------------------------


def encrypt_bytes(
    plaintext: bytes,
    passphrase: str,
    *,
    associated_data: bytes | None = None,
) -> EncryptionResult:
    """Encrypt ``plaintext`` using AES-256-GCM and a passphrase-derived key.

    Args:
        plaintext: Audio bytes to protect.
        passphrase: User passphrase. The caller is responsible for collecting
            it securely and not storing it.
        associated_data: Optional bytes to authenticate but not encrypt
            (typically the canonical metadata header).

    Returns:
        An :class:`EncryptionResult` containing the ciphertext (with the
        GCM tag appended), salt and nonce.
    """
    salt = generate_salt()
    nonce = generate_nonce()
    key = derive_key(passphrase, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

    return EncryptionResult(ciphertext=ciphertext, salt=salt, nonce=nonce)


def decrypt_bytes(
    ciphertext: bytes,
    passphrase: str,
    salt: bytes,
    nonce: bytes,
    *,
    associated_data: bytes | None = None,
) -> bytes:
    """Decrypt ``ciphertext`` produced by :func:`encrypt_bytes`.

    Args:
        ciphertext: The ciphertext + GCM tag.
        passphrase: User passphrase.
        salt: Salt that was used during encryption.
        nonce: Nonce that was used during encryption.
        associated_data: Same associated data passed to ``encrypt_bytes``.

    Returns:
        The original plaintext bytes.

    Raises:
        InvalidPassphraseError: If the passphrase is wrong or the package
            (ciphertext / nonce / salt / associated data) has been tampered
            with.
    """
    if len(nonce) != NONCE_LENGTH:
        raise ValueError(f"nonce must be {NONCE_LENGTH} bytes, got {len(nonce)}")

    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as exc:
        raise InvalidPassphraseError(
            "Decryption failed: wrong passphrase or the package has been tampered with."
        ) from exc
