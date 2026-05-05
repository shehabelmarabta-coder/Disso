"""Tests that authenticated encryption rejects any modification of the package."""

from __future__ import annotations

import io
import zipfile

import pytest

from securetrack import crypto, keys, package, recipients


def _build_package() -> bytes:
    return package.pack(
        b"audio bytes" * 200,
        recipient_specs=[recipients.PassphraseRecipient(passphrase="passphrase-1")],
        original_filename="t.wav",
    )


def _replace_zip_member(blob: bytes, name: str, new_data: bytes) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(blob), "r") as src, zipfile.ZipFile(out, "w") as dst:
        for item in src.namelist():
            data = new_data if item == name else src.read(item)
            dst.writestr(item, data)
    return out.getvalue()


def test_flipping_one_byte_in_ciphertext_fails() -> None:
    blob = _build_package()
    mutable = bytearray(blob)
    mutable[len(mutable) // 2] ^= 0x01
    with pytest.raises((crypto.InvalidPassphraseError, ValueError)):
        package.unpack(bytes(mutable), passphrase="passphrase-1")


def test_truncated_package_fails() -> None:
    blob = _build_package()
    truncated = blob[:-32]
    with pytest.raises((crypto.InvalidPassphraseError, ValueError)):
        package.unpack(truncated, passphrase="passphrase-1")


def test_tampering_with_metadata_fails() -> None:
    blob = _build_package()
    with zipfile.ZipFile(io.BytesIO(blob), "r") as zf:
        meta = zf.read(package.METADATA_FILENAME)
    # Change the first character so the JSON parser rejects the document.
    tampered = b"[" + meta[1:]
    new_blob = _replace_zip_member(blob, package.METADATA_FILENAME, tampered)
    with pytest.raises((crypto.InvalidPassphraseError, ValueError)):
        package.unpack(new_blob, passphrase="passphrase-1")


def test_tampering_with_metadata_byte_in_middle_fails() -> None:
    """A surgical change inside the metadata still invalidates GCM tags."""
    blob = _build_package()
    with zipfile.ZipFile(io.BytesIO(blob), "r") as zf:
        meta = zf.read(package.METADATA_FILENAME)
    # flip a byte inside the JSON keeping it parseable enough that the
    # package gets to the AAD-mismatch path.
    if b"sample" in meta:
        bad_meta = meta.replace(b"sample", b"smaple", 1)
    else:
        bad_meta = bytearray(meta)
        bad_meta[len(bad_meta) // 2] ^= 0x01
        bad_meta = bytes(bad_meta)
    new_blob = _replace_zip_member(blob, package.METADATA_FILENAME, bad_meta)
    with pytest.raises((crypto.InvalidPassphraseError, ValueError)):
        package.unpack(new_blob, passphrase="passphrase-1")


def test_swapping_ciphertext_for_garbage_fails() -> None:
    blob = _build_package()
    new_blob = _replace_zip_member(
        blob, package.CIPHERTEXT_FILENAME, b"\x00" * 4096
    )
    with pytest.raises((crypto.InvalidPassphraseError, ValueError)):
        package.unpack(new_blob, passphrase="passphrase-1")


def test_tampering_with_recipients_fails() -> None:
    blob = _build_package()
    with zipfile.ZipFile(io.BytesIO(blob), "r") as zf:
        recipients_bytes = zf.read(package.RECIPIENTS_FILENAME)
    mutable = bytearray(recipients_bytes)
    # flip a byte in the wrapped key (base64 region inside the JSON).
    for i in range(len(mutable)):
        if mutable[i:i + 1].isalnum():
            mutable[i] ^= 0x01
            break
    new_blob = _replace_zip_member(
        blob, package.RECIPIENTS_FILENAME, bytes(mutable)
    )
    with pytest.raises((crypto.InvalidPassphraseError, ValueError)):
        package.unpack(new_blob, passphrase="passphrase-1")


def test_signature_tamper_detected_when_one_ciphertext_byte_flipped() -> None:
    sk = keys.generate_ed25519_keypair()
    blob = package.pack(
        b"audio bytes" * 200,
        recipient_specs=[recipients.PassphraseRecipient(passphrase="pp")],
        original_filename="t.wav",
        signing_key=sk.private_key,
    )
    with zipfile.ZipFile(io.BytesIO(blob), "r") as zf:
        ciphertext = bytearray(zf.read(package.CIPHERTEXT_FILENAME))
    ciphertext[0] ^= 0x01
    new_blob = _replace_zip_member(
        blob, package.CIPHERTEXT_FILENAME, bytes(ciphertext)
    )
    with pytest.raises(crypto.InvalidSignatureError):
        package.unpack(
            new_blob, passphrase="pp", expected_signing_pubkey=sk.public_key
        )


def test_non_zip_input_raises_value_error() -> None:
    with pytest.raises(ValueError):
        package.unpack(b"this is not a zip file at all", passphrase="pp")
