"""Tests that authenticated encryption rejects any modification of the package."""

from __future__ import annotations

import io
import zipfile

import pytest

from securetrack import crypto, package


def _build_package() -> bytes:
    return package.pack(b"audio bytes" * 200, "passphrase-1", original_filename="t.wav")


def _replace_zip_member(blob: bytes, name: str, new_data: bytes) -> bytes:
    """Return a new ZIP byte string where ``name`` has been replaced with ``new_data``."""
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(blob), "r") as src, zipfile.ZipFile(out, "w") as dst:
        for item in src.namelist():
            data = new_data if item == name else src.read(item)
            dst.writestr(item, data)
    return out.getvalue()


def test_flipping_one_byte_in_ciphertext_fails() -> None:
    blob = _build_package()
    mutable = bytearray(blob)
    # Flip a byte well inside the file - regardless of where it lands
    # (zip headers, metadata, ciphertext) the unpack must fail.
    mutable[len(mutable) // 2] ^= 0x01
    with pytest.raises((crypto.InvalidPassphraseError, ValueError)):
        package.unpack(bytes(mutable), "passphrase-1")


def test_truncated_package_fails() -> None:
    blob = _build_package()
    truncated = blob[:-32]
    with pytest.raises((crypto.InvalidPassphraseError, ValueError)):
        package.unpack(truncated, "passphrase-1")


def test_tampering_with_metadata_fails() -> None:
    blob = _build_package()
    with zipfile.ZipFile(io.BytesIO(blob), "r") as zf:
        meta = zf.read(package.METADATA_FILENAME)
    # Replace the recorded original_size_bytes with a clearly wrong value.
    tampered = meta.replace(b'"original_size_bytes":2200', b'"original_size_bytes":9999')
    if tampered == meta:
        # Fall back to corrupting the first byte of the JSON if the
        # exact substring is not present (size depends on payload).
        tampered = b"{" + meta[1:]
    new_blob = _replace_zip_member(blob, package.METADATA_FILENAME, tampered)
    with pytest.raises((crypto.InvalidPassphraseError, ValueError)):
        package.unpack(new_blob, "passphrase-1")


def test_swapping_ciphertext_for_garbage_fails() -> None:
    blob = _build_package()
    new_blob = _replace_zip_member(
        blob, package.CIPHERTEXT_FILENAME, b"\x00" * 4096
    )
    with pytest.raises((crypto.InvalidPassphraseError, ValueError)):
        package.unpack(new_blob, "passphrase-1")


def test_non_zip_input_raises_value_error() -> None:
    with pytest.raises(ValueError):
        package.unpack(b"this is not a zip file at all", "pp")
