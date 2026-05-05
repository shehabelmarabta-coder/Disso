"""SecureTrack ``.securetrack`` package format (version 2).

A v2 package is a ZIP archive (``ZIP_STORED``) with up to four members:

* ``metadata.json``       — UTF-8 JSON document, also used as the AES-GCM
  associated data for *every* chunk. Contains the algorithm names, the
  KDF parameters, the chunk size, the random nonce prefix, the
  original filename, the original size, the original SHA-256, the
  ciphertext SHA-256 (used by the signature), an optional creator
  block, optional labels and (when signed) the Ed25519 verification
  key.
* ``recipients.json``     — list of wrapped content-key entries.
  Each entry is either a passphrase wrap (Scrypt + AES-GCM) or an
  X25519 wrap (ECDH + HKDF + AES-GCM). See :mod:`securetrack.recipients`.
* ``encrypted_audio.bin`` — concatenated AES-256-GCM chunks. Each chunk
  uses a derived nonce (8-byte random prefix || 4-byte big-endian
  chunk index) and authenticates ``metadata_bytes || u32(index) ||
  u32(num_chunks)`` as associated data.
* ``signature.bin``       — *optional*. Present iff the package was signed
  with an Ed25519 signing key. The signed message is
  ``metadata_bytes || sha256(recipients.json) || sha256(encrypted_audio.bin)``,
  and the verification key is recorded inside ``metadata.json``.

Pre-existing single-blob v1 packages are no longer supported; the
prototype is still pre-release so this is acceptable.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import io
import json
import math
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from . import __version__, crypto, keys, recipients

PACKAGE_FORMAT_VERSION: int = 2
METADATA_FILENAME: str = "metadata.json"
RECIPIENTS_FILENAME: str = "recipients.json"
CIPHERTEXT_FILENAME: str = "encrypted_audio.bin"
SIGNATURE_FILENAME: str = "signature.bin"


# --- metadata --------------------------------------------------------------


@dataclass
class PackageMetadata:
    """Authenticated metadata stored inside a ``.securetrack`` package.

    Note: the ciphertext digest is *not* stored here, because including
    it would create a circular dependency (metadata is AAD for every
    chunk, so any change to the metadata changes the GCM tags and
    therefore the ciphertext digest). The signature verifies a freshly
    computed digest of the ciphertext at read time instead.
    """

    algorithm: str
    kdf: str
    kdf_params: dict[str, int]
    chunk_size: int
    num_chunks: int
    nonce_prefix: bytes
    original_filename: str
    original_size_bytes: int
    sha256_original: str
    created_utc: str
    tool_version: str
    labels: dict[str, str] = field(default_factory=dict)
    creator: dict[str, str] = field(default_factory=dict)
    signature_algorithm: str | None = None
    signing_pubkey: bytes | None = None
    format_version: int = PACKAGE_FORMAT_VERSION

    # ---- (de)serialisation ------------------------------------------------

    def to_json_bytes(self) -> bytes:
        """Return the canonical JSON representation used as AAD."""
        payload: dict[str, Any] = {
            "format_version": self.format_version,
            "algorithm": self.algorithm,
            "kdf": self.kdf,
            "kdf_params": self.kdf_params,
            "chunk_size": self.chunk_size,
            "num_chunks": self.num_chunks,
            "nonce_prefix": _b64(self.nonce_prefix),
            "original_filename": self.original_filename,
            "original_size_bytes": self.original_size_bytes,
            "sha256_original": self.sha256_original,
            "created_utc": self.created_utc,
            "tool_version": self.tool_version,
            "labels": self.labels,
            "creator": self.creator,
        }
        if self.signature_algorithm is not None:
            payload["signature_algorithm"] = self.signature_algorithm
        if self.signing_pubkey is not None:
            payload["signing_pubkey"] = _b64(self.signing_pubkey)
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, raw: bytes) -> PackageMetadata:
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"metadata is not valid JSON: {exc}") from exc

        required = {
            "format_version",
            "algorithm",
            "kdf",
            "kdf_params",
            "chunk_size",
            "num_chunks",
            "nonce_prefix",
            "original_filename",
            "original_size_bytes",
            "sha256_original",
            "created_utc",
            "tool_version",
        }
        missing = required - obj.keys()
        if missing:
            raise ValueError(f"metadata is missing required fields: {sorted(missing)}")

        version = int(obj["format_version"])
        if version != PACKAGE_FORMAT_VERSION:
            raise ValueError(
                f"unsupported package format version {version}; "
                f"this build understands version {PACKAGE_FORMAT_VERSION}"
            )

        return cls(
            format_version=version,
            algorithm=str(obj["algorithm"]),
            kdf=str(obj["kdf"]),
            kdf_params=dict(obj["kdf_params"]),
            chunk_size=int(obj["chunk_size"]),
            num_chunks=int(obj["num_chunks"]),
            nonce_prefix=base64.b64decode(obj["nonce_prefix"]),
            original_filename=str(obj["original_filename"]),
            original_size_bytes=int(obj["original_size_bytes"]),
            sha256_original=str(obj["sha256_original"]),
            created_utc=str(obj["created_utc"]),
            tool_version=str(obj["tool_version"]),
            labels=dict(obj.get("labels") or {}),
            creator=dict(obj.get("creator") or {}),
            signature_algorithm=(
                str(obj["signature_algorithm"]) if "signature_algorithm" in obj else None
            ),
            signing_pubkey=(
                base64.b64decode(obj["signing_pubkey"])
                if "signing_pubkey" in obj
                else None
            ),
        )


# --- helpers ---------------------------------------------------------------


def sha256_hex(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def _utc_now_iso() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _serialise_recipients(entries: list[recipients.WrappedRecipient]) -> bytes:
    payload = {"recipients": [e.to_json_obj() for e in entries]}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _parse_recipients(raw: bytes) -> list[recipients.WrappedRecipient]:
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"recipients is not valid JSON: {exc}") from exc
    if "recipients" not in obj or not isinstance(obj["recipients"], list):
        raise ValueError("recipients.json must contain a 'recipients' list")
    return [recipients.WrappedRecipient.from_json_obj(e) for e in obj["recipients"]]


def _signature_message(
    metadata_bytes: bytes, recipients_bytes: bytes, ciphertext: bytes
) -> bytes:
    """Bytes signed by Ed25519 when a signing key is provided."""
    return (
        metadata_bytes
        + b"|"
        + hashlib.sha256(recipients_bytes).digest()
        + b"|"
        + hashlib.sha256(ciphertext).digest()
    )


# --- pack / unpack ---------------------------------------------------------


def pack(
    plaintext: bytes,
    *,
    recipient_specs: list[recipients.RecipientSpec],
    original_filename: str,
    labels: dict[str, str] | None = None,
    creator: dict[str, str] | None = None,
    chunk_size: int = crypto.DEFAULT_CHUNK_SIZE,
    signing_key: Ed25519PrivateKey | None = None,
) -> bytes:
    """Encrypt ``plaintext`` for the given recipients and return package bytes.

    Args:
        plaintext: Audio bytes to protect.
        recipient_specs: At least one recipient (passphrase or X25519
            public key). The same plaintext is wrapped once and the
            content key is wrapped per recipient.
        original_filename: File name to record inside the metadata.
        labels: Optional free-form labels (project, take, etc.).
        creator: Optional dict describing who produced the package
            (e.g. ``{"name": "alice", "host": "alice-laptop"}``).
        chunk_size: Bytes per AEAD chunk (default 1 MiB).
        signing_key: Optional Ed25519 private key. When supplied, the
            package is signed and a verification key is recorded.

    Returns:
        The bytes of the resulting ``.securetrack`` archive.
    """
    if not recipient_specs:
        raise ValueError("at least one recipient is required")
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    chunks_pt = crypto.split_into_chunks(plaintext, chunk_size)
    num_chunks = len(chunks_pt)
    nonce_prefix = crypto.generate_nonce_prefix()

    metadata = _build_metadata(
        algorithm=crypto.ALGORITHM_NAME,
        kdf=crypto.KDF_NAME,
        kdf_params=_kdf_params(),
        chunk_size=chunk_size,
        num_chunks=num_chunks,
        nonce_prefix=nonce_prefix,
        original_filename=original_filename,
        original_size_bytes=len(plaintext),
        sha256_original=sha256_hex(plaintext),
        labels=labels,
        creator=creator,
        signing_key=signing_key,
    )
    metadata_bytes = metadata.to_json_bytes()

    content_key = crypto.generate_content_key()
    ciphertext = b"".join(
        crypto.encrypt_chunks(
            chunks_pt,
            content_key=content_key,
            nonce_prefix=nonce_prefix,
            base_aad=metadata_bytes,
        )
    )

    wrapped = recipients.wrap_for_recipients(
        content_key, recipient_specs, aad=metadata_bytes
    )
    recipients_bytes = _serialise_recipients(wrapped)

    signature_bytes: bytes | None = None
    if signing_key is not None:
        sig_msg = _signature_message(metadata_bytes, recipients_bytes, ciphertext)
        signature_bytes = crypto.sign_ed25519(sig_msg, signing_key)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr(METADATA_FILENAME, metadata_bytes)
        zf.writestr(RECIPIENTS_FILENAME, recipients_bytes)
        zf.writestr(CIPHERTEXT_FILENAME, ciphertext)
        if signature_bytes is not None:
            zf.writestr(SIGNATURE_FILENAME, signature_bytes)
    return buf.getvalue()


def unpack(
    package_bytes: bytes,
    *,
    passphrase: str | None = None,
    private_key: X25519PrivateKey | None = None,
    expected_signing_pubkey: Ed25519PublicKey | None = None,
) -> tuple[PackageMetadata, bytes]:
    """Decrypt a ``.securetrack`` package and return ``(metadata, plaintext)``.

    Exactly one of ``passphrase`` or ``private_key`` (or both) must be
    supplied. If ``expected_signing_pubkey`` is given, the package
    signature must verify under it; otherwise the embedded
    ``signing_pubkey`` is used (still required to verify if a signature
    is present).
    """
    try:
        with zipfile.ZipFile(io.BytesIO(package_bytes), mode="r") as zf:
            names = set(zf.namelist())
            for required in (METADATA_FILENAME, RECIPIENTS_FILENAME, CIPHERTEXT_FILENAME):
                if required not in names:
                    raise ValueError(f"package is missing required member '{required}'")
            metadata_bytes = zf.read(METADATA_FILENAME)
            recipients_bytes = zf.read(RECIPIENTS_FILENAME)
            ciphertext = zf.read(CIPHERTEXT_FILENAME)
            signature_bytes = (
                zf.read(SIGNATURE_FILENAME) if SIGNATURE_FILENAME in names else None
            )
    except zipfile.BadZipFile as exc:
        raise ValueError(f"package is not a valid ZIP archive: {exc}") from exc

    metadata = PackageMetadata.from_json_bytes(metadata_bytes)

    # Optional signature check, before any heavy crypto.
    if signature_bytes is not None:
        if metadata.signing_pubkey is None or metadata.signature_algorithm is None:
            raise ValueError(
                "signature.bin is present but metadata has no signing key declared"
            )
        verify_pub = expected_signing_pubkey or keys.ed25519_public_from_bytes(
            metadata.signing_pubkey
        )
        sig_msg = _signature_message(metadata_bytes, recipients_bytes, ciphertext)
        crypto.verify_ed25519(sig_msg, signature_bytes, verify_pub)
    elif expected_signing_pubkey is not None:
        raise crypto.InvalidSignatureError(
            "Signature was expected but the package is unsigned."
        )

    wrapped_entries = _parse_recipients(recipients_bytes)
    content_key = recipients.unwrap_content_key(
        wrapped_entries,
        aad=metadata_bytes,
        passphrase=passphrase,
        private_key=private_key,
    )

    plaintext = crypto.decrypt_chunks(
        ciphertext,
        content_key=content_key,
        nonce_prefix=metadata.nonce_prefix,
        base_aad=metadata_bytes,
        chunk_size=metadata.chunk_size,
        num_chunks=metadata.num_chunks,
        plaintext_size=metadata.original_size_bytes,
    )

    if sha256_hex(plaintext) != metadata.sha256_original:
        raise crypto.InvalidPassphraseError(
            "Decrypted plaintext hash does not match the value recorded in the metadata."
        )

    return metadata, plaintext


# --- internal helpers ------------------------------------------------------


def _kdf_params() -> dict[str, int]:
    return {
        "n": crypto.SCRYPT_N,
        "r": crypto.SCRYPT_R,
        "p": crypto.SCRYPT_P,
        "length": crypto.KEY_LENGTH,
    }


def _build_metadata(
    *,
    algorithm: str,
    kdf: str,
    kdf_params: dict[str, int],
    chunk_size: int,
    num_chunks: int,
    nonce_prefix: bytes,
    original_filename: str,
    original_size_bytes: int,
    sha256_original: str,
    labels: dict[str, str] | None,
    creator: dict[str, str] | None,
    signing_key: Ed25519PrivateKey | None,
) -> PackageMetadata:
    signing_pubkey = (
        keys.ed25519_public_bytes(signing_key.public_key()) if signing_key else None
    )
    return PackageMetadata(
        algorithm=algorithm,
        kdf=kdf,
        kdf_params=kdf_params,
        chunk_size=chunk_size,
        num_chunks=num_chunks,
        nonce_prefix=nonce_prefix,
        original_filename=original_filename,
        original_size_bytes=original_size_bytes,
        sha256_original=sha256_original,
        created_utc=_utc_now_iso(),
        tool_version=__version__,
        labels=dict(labels or {}),
        creator=dict(creator or {}),
        signature_algorithm=crypto.SIGNATURE_ALGORITHM_NAME if signing_key else None,
        signing_pubkey=signing_pubkey,
    )


# --- file convenience wrappers --------------------------------------------


def encrypt_file(
    input_path: Path,
    output_path: Path,
    *,
    recipient_specs: list[recipients.RecipientSpec],
    labels: dict[str, str] | None = None,
    creator: dict[str, str] | None = None,
    chunk_size: int = crypto.DEFAULT_CHUNK_SIZE,
    signing_key: Ed25519PrivateKey | None = None,
) -> PackageMetadata:
    """Read ``input_path``, write a v2 ``.securetrack`` package to ``output_path``."""
    plaintext = Path(input_path).read_bytes()
    blob = pack(
        plaintext,
        recipient_specs=recipient_specs,
        original_filename=Path(input_path).name,
        labels=labels,
        creator=creator,
        chunk_size=chunk_size,
        signing_key=signing_key,
    )
    Path(output_path).write_bytes(blob)
    return read_metadata_from_bytes(blob)


def decrypt_file(
    input_path: Path,
    output_path: Path,
    *,
    passphrase: str | None = None,
    private_key: X25519PrivateKey | None = None,
    expected_signing_pubkey: Ed25519PublicKey | None = None,
) -> PackageMetadata:
    """Read a v2 ``.securetrack`` package, write the original audio to ``output_path``."""
    blob = Path(input_path).read_bytes()
    metadata, plaintext = unpack(
        blob,
        passphrase=passphrase,
        private_key=private_key,
        expected_signing_pubkey=expected_signing_pubkey,
    )
    Path(output_path).write_bytes(plaintext)
    return metadata


def read_metadata(input_path: Path) -> PackageMetadata:
    """Return the metadata of a ``.securetrack`` package without decrypting it."""
    return read_metadata_from_bytes(Path(input_path).read_bytes())


def read_metadata_from_bytes(blob: bytes) -> PackageMetadata:
    """Return the metadata of an in-memory package without decrypting it."""
    try:
        with zipfile.ZipFile(io.BytesIO(blob), mode="r") as zf:
            metadata_bytes = zf.read(METADATA_FILENAME)
    except (zipfile.BadZipFile, KeyError) as exc:
        raise ValueError(f"package is malformed: {exc}") from exc
    return PackageMetadata.from_json_bytes(metadata_bytes)


def expected_num_chunks(plaintext_size: int, chunk_size: int) -> int:
    """How many chunks ``pack`` will produce for a plaintext of this size."""
    if plaintext_size == 0:
        return 1
    return math.ceil(plaintext_size / chunk_size)
