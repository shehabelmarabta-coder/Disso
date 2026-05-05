"""Security tests.

Verifies that the prototype rejects every form of tampering it
claims to defend against: wrong passphrase, wrong private key,
mutated bytes anywhere in the package, truncation, chunk
reordering, AAD mismatch, missing or wrong signatures, and
malformed input.
"""

from __future__ import annotations

import io
import os
import zipfile
from pathlib import Path

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


# --- passphrase / key authentication --------------------------------------


def test_wrong_passphrase_raises() -> None:
    blob = package.pack(
        b"secret bytes",
        recipient_specs=[recipients.PassphraseRecipient(passphrase="good")],
        original_filename="x.wav",
    )
    with pytest.raises(crypto.InvalidPassphraseError):
        package.unpack(blob, passphrase="WRONG")


def test_pubkey_wrong_private_key_fails() -> None:
    right = keys.generate_x25519_keypair()
    wrong = keys.generate_x25519_keypair()
    blob = package.pack(
        b"secret",
        recipient_specs=[recipients.PublicKeyRecipient(public_key=right.public_key)],
        original_filename="t.wav",
    )
    with pytest.raises(crypto.InvalidPassphraseError):
        package.unpack(blob, private_key=wrong.private_key)


def test_passphrase_wrap_wrong_passphrase_fails() -> None:
    content_key = os.urandom(crypto.KEY_LENGTH)
    entry = recipients.wrap_for_passphrase(content_key, "right", aad=b"a")
    with pytest.raises(crypto.InvalidPassphraseError):
        recipients.unwrap_with_passphrase(entry, "wrong", aad=b"a")


def test_pubkey_wrap_wrong_private_key_fails_at_recipient_layer() -> None:
    right = keys.generate_x25519_keypair()
    wrong = keys.generate_x25519_keypair()
    content_key = os.urandom(crypto.KEY_LENGTH)
    entry = recipients.wrap_for_pubkey(content_key, right.public_key, aad=b"a")
    with pytest.raises(crypto.InvalidPassphraseError):
        recipients.unwrap_with_private_key(entry, wrong.private_key, aad=b"a")


def test_unwrap_with_neither_credential_raises() -> None:
    content_key = os.urandom(crypto.KEY_LENGTH)
    entries = [recipients.wrap_for_passphrase(content_key, "pp", aad=b"a")]
    with pytest.raises(ValueError):
        recipients.unwrap_content_key(entries, aad=b"a")


# --- single-byte / truncation tampering -----------------------------------


def test_flipping_one_byte_in_ciphertext_fails() -> None:
    blob = _build_package()
    mutable = bytearray(blob)
    mutable[len(mutable) // 2] ^= 0x01
    with pytest.raises((crypto.InvalidPassphraseError, ValueError)):
        package.unpack(bytes(mutable), passphrase="passphrase-1")


def test_truncated_package_fails() -> None:
    blob = _build_package()
    with pytest.raises((crypto.InvalidPassphraseError, ValueError)):
        package.unpack(blob[:-32], passphrase="passphrase-1")


# --- header tampering -----------------------------------------------------


def test_tampering_with_metadata_fails() -> None:
    blob = _build_package()
    with zipfile.ZipFile(io.BytesIO(blob), "r") as zf:
        meta = zf.read(package.METADATA_FILENAME)
    tampered = b"[" + meta[1:]  # break the JSON object opening
    new_blob = _replace_zip_member(blob, package.METADATA_FILENAME, tampered)
    with pytest.raises((crypto.InvalidPassphraseError, ValueError)):
        package.unpack(new_blob, passphrase="passphrase-1")


def test_tampering_with_metadata_byte_in_middle_fails() -> None:
    """A surgical change inside the JSON still invalidates the GCM tags."""
    blob = _build_package()
    with zipfile.ZipFile(io.BytesIO(blob), "r") as zf:
        meta = zf.read(package.METADATA_FILENAME)
    bad = bytearray(meta)
    bad[len(bad) // 2] ^= 0x01
    new_blob = _replace_zip_member(blob, package.METADATA_FILENAME, bytes(bad))
    with pytest.raises((crypto.InvalidPassphraseError, ValueError)):
        package.unpack(new_blob, passphrase="passphrase-1")


def test_tampering_with_recipients_fails() -> None:
    blob = _build_package()
    with zipfile.ZipFile(io.BytesIO(blob), "r") as zf:
        recipients_bytes = zf.read(package.RECIPIENTS_FILENAME)
    mutable = bytearray(recipients_bytes)
    for i, byte_value in enumerate(mutable):
        if chr(byte_value).isalnum():
            mutable[i] ^= 0x01
            break
    new_blob = _replace_zip_member(
        blob, package.RECIPIENTS_FILENAME, bytes(mutable)
    )
    with pytest.raises((crypto.InvalidPassphraseError, ValueError)):
        package.unpack(new_blob, passphrase="passphrase-1")


def test_swapping_ciphertext_for_garbage_fails() -> None:
    blob = _build_package()
    new_blob = _replace_zip_member(
        blob, package.CIPHERTEXT_FILENAME, b"\x00" * 4096
    )
    with pytest.raises((crypto.InvalidPassphraseError, ValueError)):
        package.unpack(new_blob, passphrase="passphrase-1")


def test_non_zip_input_raises_value_error() -> None:
    with pytest.raises(ValueError):
        package.unpack(b"this is not a zip file at all", passphrase="pp")


# --- chunk-level tampering -----------------------------------------------


def _aad() -> bytes:
    return b"test-aad-for-streaming"


def test_streaming_rejects_chunk_reorder() -> None:
    plaintext = b"chunk0_chunk1_chunk2_"
    content_key = crypto.generate_content_key()
    nonce_prefix = crypto.generate_nonce_prefix()
    chunks = crypto.split_into_chunks(plaintext, 7)
    cts = list(
        crypto.encrypt_chunks(
            chunks, content_key=content_key, nonce_prefix=nonce_prefix, base_aad=_aad()
        )
    )
    swapped = cts[1] + cts[0] + cts[2]
    with pytest.raises(crypto.InvalidPassphraseError):
        crypto.decrypt_chunks(
            swapped,
            content_key=content_key,
            nonce_prefix=nonce_prefix,
            base_aad=_aad(),
            chunk_size=7,
            num_chunks=3,
            plaintext_size=len(plaintext),
        )


def test_streaming_rejects_truncation() -> None:
    plaintext = b"abcdefghij" * 1024
    content_key = crypto.generate_content_key()
    nonce_prefix = crypto.generate_nonce_prefix()
    chunks = crypto.split_into_chunks(plaintext, 1024)
    ciphertext = b"".join(
        crypto.encrypt_chunks(
            chunks, content_key=content_key, nonce_prefix=nonce_prefix, base_aad=_aad()
        )
    )
    with pytest.raises(crypto.InvalidPassphraseError):
        crypto.decrypt_chunks(
            ciphertext[:-50],
            content_key=content_key,
            nonce_prefix=nonce_prefix,
            base_aad=_aad(),
            chunk_size=1024,
            num_chunks=len(chunks),
            plaintext_size=len(plaintext),
        )


def test_streaming_rejects_wrong_aad() -> None:
    plaintext = b"data" * 1024
    content_key = crypto.generate_content_key()
    nonce_prefix = crypto.generate_nonce_prefix()
    chunks = crypto.split_into_chunks(plaintext, 1024)
    ciphertext = b"".join(
        crypto.encrypt_chunks(
            chunks,
            content_key=content_key,
            nonce_prefix=nonce_prefix,
            base_aad=b"original-aad",
        )
    )
    with pytest.raises(crypto.InvalidPassphraseError):
        crypto.decrypt_chunks(
            ciphertext,
            content_key=content_key,
            nonce_prefix=nonce_prefix,
            base_aad=b"different-aad",
            chunk_size=1024,
            num_chunks=len(chunks),
            plaintext_size=len(plaintext),
        )


# --- signature tests ------------------------------------------------------


def test_signed_package_unsigned_expected_raises() -> None:
    sk = keys.generate_ed25519_keypair()
    blob = package.pack(
        b"unsigned",
        recipient_specs=[recipients.PassphraseRecipient(passphrase="pp")],
        original_filename="t.wav",
    )
    with pytest.raises(crypto.InvalidSignatureError):
        package.unpack(blob, passphrase="pp", expected_signing_pubkey=sk.public_key)


def test_signed_package_wrong_signer_raises() -> None:
    real = keys.generate_ed25519_keypair()
    other = keys.generate_ed25519_keypair()
    blob = package.pack(
        b"audio",
        recipient_specs=[recipients.PassphraseRecipient(passphrase="pp")],
        original_filename="t.wav",
        signing_key=real.private_key,
    )
    with pytest.raises(crypto.InvalidSignatureError):
        package.unpack(blob, passphrase="pp", expected_signing_pubkey=other.public_key)


def test_signature_detects_one_byte_ciphertext_flip() -> None:
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
    new_blob = _replace_zip_member(blob, package.CIPHERTEXT_FILENAME, bytes(ciphertext))
    with pytest.raises(crypto.InvalidSignatureError):
        package.unpack(
            new_blob, passphrase="pp", expected_signing_pubkey=sk.public_key
        )


# --- key file at-rest protection ------------------------------------------


def test_x25519_private_key_is_passphrase_protected(tmp_path: Path) -> None:
    kp = keys.generate_x25519_keypair()
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    keys.write_keypair(kp, private_path=priv, public_path=pub, passphrase="hunter2")
    with pytest.raises(Exception):
        keys.load_x25519_private(priv)
    with pytest.raises(Exception):
        keys.load_x25519_private(priv, passphrase="wrong")
    keys.load_x25519_private(priv, passphrase="hunter2")  # success


def test_loading_wrong_key_kind_errors(tmp_path: Path) -> None:
    x_kp = keys.generate_x25519_keypair()
    priv = tmp_path / "x.pem"
    pub = tmp_path / "x_pub.pem"
    keys.write_keypair(x_kp, private_path=priv, public_path=pub)
    with pytest.raises(ValueError):
        keys.load_ed25519_private(priv)
    with pytest.raises(ValueError):
        keys.load_ed25519_public(pub)


def test_private_key_file_mode_is_600_on_posix(tmp_path: Path) -> None:
    if os.name != "posix":
        pytest.skip("POSIX-only file-mode check")
    kp = keys.generate_x25519_keypair()
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    keys.write_keypair(kp, private_path=priv, public_path=pub)
    assert (priv.stat().st_mode & 0o777) == 0o600


# --- per-package nonce uniqueness -----------------------------------------


def test_two_packages_use_different_nonce_prefix() -> None:
    a, _ = package.unpack(
        package.pack(
            b"x", recipient_specs=[recipients.PassphraseRecipient(passphrase="p")],
            original_filename="a",
        ),
        passphrase="p",
    )
    b, _ = package.unpack(
        package.pack(
            b"x", recipient_specs=[recipients.PassphraseRecipient(passphrase="p")],
            original_filename="a",
        ),
        passphrase="p",
    )
    assert a.nonce_prefix != b.nonce_prefix
