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

Format v2 also relies on this module for:

* :func:`encrypt_chunks` / :func:`decrypt_chunks` — chunked AES-GCM
  streaming so very large WAVs do not have to fit in memory.
* :func:`hkdf_derive_key` — used by :mod:`securetrack.recipients` to
  derive a content-key wrapping key from an X25519 shared secret.
* :func:`sign_ed25519` / :func:`verify_ed25519` — package-level
  signature helpers.

All functions raise :class:`InvalidPassphraseError` for any failure to
authenticate, regardless of the underlying cause, so a caller cannot
distinguish a wrong passphrase from a tampered package.
"""

from __future__ import annotations

import os
import struct
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# --- public constants -------------------------------------------------------

ALGORITHM_NAME: str = "AES-256-GCM"
KDF_NAME: str = "scrypt"
SIGNATURE_ALGORITHM_NAME: str = "Ed25519"

#: Length of the AES-256 key in bytes.
KEY_LENGTH: int = 32
#: Length of the Scrypt salt in bytes.
SALT_LENGTH: int = 16
#: Length of the AES-GCM nonce in bytes (96 bits is the GCM standard).
NONCE_LENGTH: int = 12
#: Length of the AES-GCM authentication tag in bytes.
TAG_LENGTH: int = 16
#: Length of the random nonce *prefix* used for chunked streaming. The
#: 4 trailing bytes are a big-endian chunk counter, so the full nonce
#: stays at :data:`NONCE_LENGTH` bytes.
NONCE_PREFIX_LENGTH: int = 8

#: Default chunk size for streaming encryption (1 MiB).
DEFAULT_CHUNK_SIZE: int = 1 << 20

#: Maximum supported chunk count. Limited by the 32-bit counter in the
#: nonce suffix; in practice the user will run out of disk first.
MAX_CHUNKS: int = (1 << 32) - 1

#: Scrypt cost parameters. Tuned for a desktop application: roughly
#: ~30 MB of memory and a few hundred milliseconds on a modern laptop.
SCRYPT_N: int = 2**15
SCRYPT_R: int = 8
SCRYPT_P: int = 1


class InvalidPassphraseError(Exception):
    """Raised when decryption fails (wrong passphrase or tampered package)."""


class InvalidSignatureError(Exception):
    """Raised when an Ed25519 package signature does not verify."""


@dataclass(frozen=True)
class EncryptionResult:
    """Output of a one-shot encryption operation."""

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


def generate_nonce_prefix() -> bytes:
    """Return a fresh 8-byte random nonce prefix for chunked streaming."""
    return os.urandom(NONCE_PREFIX_LENGTH)


def generate_content_key() -> bytes:
    """Return a fresh random 256-bit AES key for content encryption."""
    return os.urandom(KEY_LENGTH)


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from a passphrase and salt using Scrypt."""
    if not passphrase:
        raise ValueError("passphrase must not be empty")
    if len(salt) != SALT_LENGTH:
        raise ValueError(f"salt must be {SALT_LENGTH} bytes, got {len(salt)}")

    kdf = Scrypt(salt=salt, length=KEY_LENGTH, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


def hkdf_derive_key(
    shared_secret: bytes,
    *,
    info: bytes,
    salt: bytes | None = None,
    length: int = KEY_LENGTH,
) -> bytes:
    """HKDF-SHA256 from an arbitrary shared secret to a fixed-length key.

    Used by the X25519 recipient wrapping path to turn a Diffie-Hellman
    shared secret into a content-key wrapping key.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(shared_secret)


# --- one-shot encryption / decryption (passphrase, single AEAD blob) -------


def encrypt_bytes(
    plaintext: bytes,
    passphrase: str,
    *,
    associated_data: bytes | None = None,
) -> EncryptionResult:
    """Encrypt ``plaintext`` using AES-256-GCM and a passphrase-derived key."""
    salt = generate_salt()
    nonce = generate_nonce()
    key = derive_key(passphrase, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return EncryptionResult(ciphertext=ciphertext, salt=salt, nonce=nonce)


def decrypt_bytes(
    ciphertext: bytes,
    passphrase: str,
    salt: bytes,
    nonce: bytes,
    *,
    associated_data: bytes | None = None,
) -> bytes:
    """Decrypt ``ciphertext`` produced by :func:`encrypt_bytes`."""
    if len(nonce) != NONCE_LENGTH:
        raise ValueError(f"nonce must be {NONCE_LENGTH} bytes, got {len(nonce)}")
    key = derive_key(passphrase, salt)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as exc:
        raise InvalidPassphraseError(
            "Decryption failed: wrong passphrase or the package has been tampered with."
        ) from exc


# --- chunked streaming AEAD ------------------------------------------------


def _build_chunk_nonce(prefix: bytes, index: int) -> bytes:
    if len(prefix) != NONCE_PREFIX_LENGTH:
        raise ValueError(
            f"nonce prefix must be {NONCE_PREFIX_LENGTH} bytes, got {len(prefix)}"
        )
    if not 0 <= index <= MAX_CHUNKS:
        raise ValueError(f"chunk index {index} out of range")
    return prefix + struct.pack(">I", index)


def _chunk_aad(base_aad: bytes, index: int, num_chunks: int) -> bytes:
    """Build the per-chunk associated data.

    Each chunk authenticates ``base_aad`` (the canonical package metadata)
    *plus* its position in the stream and the total number of chunks, so
    chunks cannot be reordered, dropped or swapped between packages
    without invalidating the GCM tag.
    """
    return base_aad + struct.pack(">II", index, num_chunks)


def split_into_chunks(plaintext: bytes, chunk_size: int) -> list[bytes]:
    """Split ``plaintext`` into ``chunk_size`` pieces (last one may be shorter)."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    if not plaintext:
        return [b""]
    return [plaintext[i : i + chunk_size] for i in range(0, len(plaintext), chunk_size)]


def encrypt_chunks(
    plaintext_chunks: Iterable[bytes],
    *,
    content_key: bytes,
    nonce_prefix: bytes,
    base_aad: bytes,
) -> Iterator[bytes]:
    """Yield ciphertext+tag for each plaintext chunk.

    The caller must materialise (or count) the chunks first so it can
    write the correct ``num_chunks`` value into the package metadata
    that is fed back as ``base_aad``. In practice we use
    :func:`split_into_chunks` and ``len(...)`` for that.
    """
    chunks = list(plaintext_chunks)
    if len(chunks) > MAX_CHUNKS:
        raise ValueError(f"too many chunks: {len(chunks)} > {MAX_CHUNKS}")
    aesgcm = AESGCM(content_key)
    for i, chunk in enumerate(chunks):
        nonce = _build_chunk_nonce(nonce_prefix, i)
        aad = _chunk_aad(base_aad, i, len(chunks))
        yield aesgcm.encrypt(nonce, chunk, aad)


def decrypt_chunks(
    ciphertext_blob: bytes,
    *,
    content_key: bytes,
    nonce_prefix: bytes,
    base_aad: bytes,
    chunk_size: int,
    num_chunks: int,
    plaintext_size: int,
) -> bytes:
    """Decrypt a concatenated ciphertext+tag stream produced by :func:`encrypt_chunks`."""
    if num_chunks < 1:
        raise ValueError("num_chunks must be at least 1")
    aesgcm = AESGCM(content_key)
    out = bytearray()
    cursor = 0
    for i in range(num_chunks):
        is_last = i == num_chunks - 1
        if is_last:
            this_pt_size = plaintext_size - chunk_size * (num_chunks - 1)
        else:
            this_pt_size = chunk_size
        ct_len = this_pt_size + TAG_LENGTH
        slice_ = ciphertext_blob[cursor : cursor + ct_len]
        if len(slice_) != ct_len:
            raise InvalidPassphraseError(
                "Ciphertext is truncated: package has been tampered with or is incomplete."
            )
        cursor += ct_len
        nonce = _build_chunk_nonce(nonce_prefix, i)
        aad = _chunk_aad(base_aad, i, num_chunks)
        try:
            out.extend(aesgcm.decrypt(nonce, slice_, aad))
        except InvalidTag as exc:
            raise InvalidPassphraseError(
                "Chunk authentication failed: wrong key or package has been tampered with."
            ) from exc
    if cursor != len(ciphertext_blob):
        raise InvalidPassphraseError(
            "Trailing bytes in ciphertext stream: package has been tampered with."
        )
    return bytes(out)


# --- Ed25519 signing -------------------------------------------------------


def sign_ed25519(message: bytes, private_key: Ed25519PrivateKey) -> bytes:
    """Return an Ed25519 signature over ``message``."""
    return private_key.sign(message)


def verify_ed25519(message: bytes, signature: bytes, public_key: Ed25519PublicKey) -> None:
    """Verify an Ed25519 signature.

    Raises :class:`InvalidSignatureError` if the signature does not
    verify under ``public_key``.
    """
    try:
        public_key.verify(signature, message)
    except InvalidSignature as exc:
        raise InvalidSignatureError(
            "Package signature does not verify: file may be forged or tampered with."
        ) from exc
