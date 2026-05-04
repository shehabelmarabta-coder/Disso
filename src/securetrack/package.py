"""SecureTrack package format.

A ``.securetrack`` file is a standard ZIP archive that contains exactly
two members:

* ``metadata.json`` - a UTF-8 JSON document describing how to decrypt the
  payload, plus authenticated metadata about the original file.
* ``encrypted_audio.bin`` - the AES-256-GCM ciphertext (with the 16-byte
  GCM tag appended).

A ZIP container was chosen over a custom binary format because it is
trivial to inspect with standard tools, the format is robust, and the
overhead is small (~200 bytes for the central directory). Inspecting the
metadata of a package without decrypting it is intentional - it lets a
recipient see what the package claims to contain before typing a
passphrase.

Metadata schema (version 1)
---------------------------
{
    "format_version": 1,
    "algorithm":      "AES-256-GCM",
    "kdf":            "scrypt",
    "kdf_params":     {"n": 32768, "r": 8, "p": 1, "length": 32},
    "salt":           "<base64>",
    "nonce":          "<base64>",
    "original_filename":  "sample.wav",
    "original_size_bytes": 88244,
    "sha256_original":     "<hex>",
    "created_utc":         "2026-05-04T12:00:00Z",
    "labels": {                    # optional, free-form
        "project": "...",
        "collaborator": "..."
    }
}

The serialised metadata is also bound to the ciphertext as AES-GCM
*associated data*, so any modification of the metadata invalidates the
authentication tag.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import io
import json
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import crypto

PACKAGE_FORMAT_VERSION: int = 1
METADATA_FILENAME: str = "metadata.json"
CIPHERTEXT_FILENAME: str = "encrypted_audio.bin"


# --- metadata --------------------------------------------------------------


@dataclass
class PackageMetadata:
    """Authenticated metadata stored inside a ``.securetrack`` package."""

    algorithm: str
    kdf: str
    kdf_params: dict[str, int]
    salt: bytes
    nonce: bytes
    original_filename: str
    original_size_bytes: int
    sha256_original: str
    created_utc: str
    labels: dict[str, str] = field(default_factory=dict)
    format_version: int = PACKAGE_FORMAT_VERSION

    # ---- (de)serialisation ------------------------------------------------

    def to_json_bytes(self) -> bytes:
        """Return the canonical JSON representation used as AAD."""
        payload: dict[str, Any] = {
            "format_version": self.format_version,
            "algorithm": self.algorithm,
            "kdf": self.kdf,
            "kdf_params": self.kdf_params,
            "salt": base64.b64encode(self.salt).decode("ascii"),
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "original_filename": self.original_filename,
            "original_size_bytes": self.original_size_bytes,
            "sha256_original": self.sha256_original,
            "created_utc": self.created_utc,
            "labels": self.labels,
        }
        # sort_keys gives a stable byte-for-byte representation, which is
        # important because the same bytes are used as AES-GCM associated
        # data during both encryption and decryption.
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, raw: bytes) -> PackageMetadata:
        """Parse metadata from its canonical JSON representation."""
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"metadata is not valid JSON: {exc}") from exc

        required = {
            "format_version",
            "algorithm",
            "kdf",
            "kdf_params",
            "salt",
            "nonce",
            "original_filename",
            "original_size_bytes",
            "sha256_original",
            "created_utc",
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
            salt=base64.b64decode(obj["salt"]),
            nonce=base64.b64decode(obj["nonce"]),
            original_filename=str(obj["original_filename"]),
            original_size_bytes=int(obj["original_size_bytes"]),
            sha256_original=str(obj["sha256_original"]),
            created_utc=str(obj["created_utc"]),
            labels=dict(obj.get("labels") or {}),
        )


# --- helpers ---------------------------------------------------------------


def sha256_hex(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def _utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string with a ``Z`` suffix."""
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


# --- pack / unpack ---------------------------------------------------------


def pack(
    plaintext: bytes,
    passphrase: str,
    original_filename: str,
    *,
    labels: dict[str, str] | None = None,
) -> bytes:
    """Encrypt ``plaintext`` and return the bytes of a ``.securetrack`` package.

    The function performs all the steps required to produce a portable
    package: hashing the original audio, deriving a key from the
    passphrase, encrypting under AES-GCM with the metadata as AAD, and
    finally writing both members into a ZIP archive in memory.
    """
    # Generate salt and nonce up front so we can build the metadata
    # before encrypting. The same metadata bytes are then used as the
    # AES-GCM associated data, binding the metadata to the ciphertext.
    salt = crypto.generate_salt()
    nonce = crypto.generate_nonce()

    metadata = PackageMetadata(
        algorithm=crypto.ALGORITHM_NAME,
        kdf=crypto.KDF_NAME,
        kdf_params={
            "n": crypto.SCRYPT_N,
            "r": crypto.SCRYPT_R,
            "p": crypto.SCRYPT_P,
            "length": crypto.KEY_LENGTH,
        },
        salt=salt,
        nonce=nonce,
        original_filename=original_filename,
        original_size_bytes=len(plaintext),
        sha256_original=sha256_hex(plaintext),
        created_utc=_utc_now_iso(),
        labels=dict(labels or {}),
    )
    metadata_bytes = metadata.to_json_bytes()

    key = crypto.derive_key(passphrase, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, metadata_bytes)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr(METADATA_FILENAME, metadata_bytes)
        zf.writestr(CIPHERTEXT_FILENAME, ciphertext)
    return buf.getvalue()


def unpack(package_bytes: bytes, passphrase: str) -> tuple[PackageMetadata, bytes]:
    """Decrypt a ``.securetrack`` package and return ``(metadata, plaintext)``.

    Raises:
        ValueError: If the archive is malformed or missing required members.
        crypto.InvalidPassphraseError: If decryption / authentication fails.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(package_bytes), mode="r") as zf:
            names = set(zf.namelist())
            for required in (METADATA_FILENAME, CIPHERTEXT_FILENAME):
                if required not in names:
                    raise ValueError(
                        f"package is missing required member '{required}'"
                    )
            metadata_bytes = zf.read(METADATA_FILENAME)
            ciphertext = zf.read(CIPHERTEXT_FILENAME)
    except zipfile.BadZipFile as exc:
        raise ValueError(f"package is not a valid ZIP archive: {exc}") from exc

    metadata = PackageMetadata.from_json_bytes(metadata_bytes)

    plaintext = crypto.decrypt_bytes(
        ciphertext,
        passphrase,
        salt=metadata.salt,
        nonce=metadata.nonce,
        associated_data=metadata_bytes,
    )

    # Defence-in-depth: even though GCM already authenticated the data,
    # verify the SHA-256 hash of the plaintext matches what the metadata
    # claims. This catches corner cases such as accidental truncation
    # before the package was sealed.
    actual_hash = sha256_hex(plaintext)
    if actual_hash != metadata.sha256_original:
        raise crypto.InvalidPassphraseError(
            "Decrypted plaintext hash does not match the value recorded in the metadata."
        )

    return metadata, plaintext


# --- file convenience wrappers --------------------------------------------


def encrypt_file(
    input_path: Path,
    output_path: Path,
    passphrase: str,
    *,
    labels: dict[str, str] | None = None,
) -> PackageMetadata:
    """Read ``input_path``, write a ``.securetrack`` package to ``output_path``."""
    plaintext = Path(input_path).read_bytes()
    package_bytes = pack(
        plaintext,
        passphrase,
        original_filename=Path(input_path).name,
        labels=labels,
    )
    Path(output_path).write_bytes(package_bytes)
    # Re-read the metadata from the freshly written package so the caller
    # sees exactly what is on disk.
    metadata, _ = unpack(package_bytes, passphrase)
    return metadata


def decrypt_file(input_path: Path, output_path: Path, passphrase: str) -> PackageMetadata:
    """Read a ``.securetrack`` package, write the original audio to ``output_path``."""
    package_bytes = Path(input_path).read_bytes()
    metadata, plaintext = unpack(package_bytes, passphrase)
    Path(output_path).write_bytes(plaintext)
    return metadata


def read_metadata(input_path: Path) -> PackageMetadata:
    """Return the metadata of a ``.securetrack`` package without decrypting it."""
    package_bytes = Path(input_path).read_bytes()
    try:
        with zipfile.ZipFile(io.BytesIO(package_bytes), mode="r") as zf:
            metadata_bytes = zf.read(METADATA_FILENAME)
    except (zipfile.BadZipFile, KeyError) as exc:
        raise ValueError(f"package is malformed: {exc}") from exc
    return PackageMetadata.from_json_bytes(metadata_bytes)
