"""Round-trip correctness tests for SecureTrack v2 packages."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from securetrack import crypto, keys, package, recipients


def _passphrase_specs(pp: str = "correct horse battery staple") -> list[recipients.RecipientSpec]:
    return [recipients.PassphraseRecipient(passphrase=pp)]


def test_encrypt_then_decrypt_returns_exact_plaintext() -> None:
    plaintext = b"the quick brown fox jumps over the lazy dog" * 1000
    blob = package.pack(
        plaintext,
        recipient_specs=_passphrase_specs(),
        original_filename="t.wav",
    )
    metadata, recovered = package.unpack(blob, passphrase="correct horse battery staple")
    assert recovered == plaintext
    assert metadata.original_filename == "t.wav"
    assert metadata.original_size_bytes == len(plaintext)
    assert metadata.format_version == package.PACKAGE_FORMAT_VERSION


def test_random_payload_roundtrip() -> None:
    plaintext = os.urandom(64 * 1024)
    blob = package.pack(
        plaintext,
        recipient_specs=_passphrase_specs("another-passphrase!"),
        original_filename="random.bin",
    )
    _, recovered = package.unpack(blob, passphrase="another-passphrase!")
    assert recovered == plaintext


def test_wrong_passphrase_raises() -> None:
    blob = package.pack(
        b"secret bytes",
        recipient_specs=_passphrase_specs("good-passphrase"),
        original_filename="x.wav",
    )
    with pytest.raises(crypto.InvalidPassphraseError):
        package.unpack(blob, passphrase="WRONG-passphrase")


def test_pack_requires_at_least_one_recipient() -> None:
    with pytest.raises(ValueError):
        package.pack(b"data", recipient_specs=[], original_filename="x.wav")


def test_metadata_round_trip_through_disk(tmp_path: Path) -> None:
    src = tmp_path / "in.wav"
    src.write_bytes(b"riff-style payload" * 100)
    pkg = tmp_path / "out.securetrack"
    out = tmp_path / "recovered.wav"

    written_meta = package.encrypt_file(
        src,
        pkg,
        recipient_specs=_passphrase_specs("pass-1234"),
        labels={"project": "demo"},
        creator={"name": "alice"},
    )
    read_meta = package.decrypt_file(pkg, out, passphrase="pass-1234")

    assert out.read_bytes() == src.read_bytes()
    assert written_meta.original_filename == "in.wav"
    assert read_meta.labels == {"project": "demo"}
    assert read_meta.creator == {"name": "alice"}


def test_package_contains_required_metadata_fields() -> None:
    plaintext = b"hello world"
    blob = package.pack(
        plaintext, recipient_specs=_passphrase_specs("pp"), original_filename="hello.wav"
    )
    metadata, _ = package.unpack(blob, passphrase="pp")
    assert metadata.algorithm == crypto.ALGORITHM_NAME
    assert metadata.kdf == crypto.KDF_NAME
    assert metadata.format_version == package.PACKAGE_FORMAT_VERSION
    assert len(metadata.nonce_prefix) == crypto.NONCE_PREFIX_LENGTH
    assert metadata.sha256_original == package.sha256_hex(plaintext)
    assert metadata.created_utc.endswith("Z")
    assert metadata.tool_version  # truthy


def test_two_packages_use_different_nonce_prefix() -> None:
    a, _ = package.unpack(
        package.pack(b"x", recipient_specs=_passphrase_specs("p"), original_filename="a"),
        passphrase="p",
    )
    b, _ = package.unpack(
        package.pack(b"x", recipient_specs=_passphrase_specs("p"), original_filename="a"),
        passphrase="p",
    )
    assert a.nonce_prefix != b.nonce_prefix


def test_pubkey_roundtrip() -> None:
    kp = keys.generate_x25519_keypair()
    plaintext = b"audio payload" * 200
    blob = package.pack(
        plaintext,
        recipient_specs=[recipients.PublicKeyRecipient(public_key=kp.public_key)],
        original_filename="t.wav",
    )
    _, recovered = package.unpack(blob, private_key=kp.private_key)
    assert recovered == plaintext


def test_pubkey_wrong_private_key_fails() -> None:
    kp_right = keys.generate_x25519_keypair()
    kp_wrong = keys.generate_x25519_keypair()
    blob = package.pack(
        b"secret",
        recipient_specs=[recipients.PublicKeyRecipient(public_key=kp_right.public_key)],
        original_filename="t.wav",
    )
    with pytest.raises(crypto.InvalidPassphraseError):
        package.unpack(blob, private_key=kp_wrong.private_key)


def test_multi_recipient_either_works() -> None:
    kp = keys.generate_x25519_keypair()
    plaintext = b"shared secret content"
    blob = package.pack(
        plaintext,
        recipient_specs=[
            recipients.PublicKeyRecipient(public_key=kp.public_key, label="alice"),
            recipients.PassphraseRecipient(passphrase="shared-pp", label="fallback"),
        ],
        original_filename="t.wav",
    )
    _, by_key = package.unpack(blob, private_key=kp.private_key)
    _, by_pp = package.unpack(blob, passphrase="shared-pp")
    assert by_key == plaintext == by_pp


def test_chunked_streaming_for_multi_chunk_payload() -> None:
    plaintext = bytes(range(256)) * 4096  # 1 MiB exactly
    blob = package.pack(
        plaintext,
        recipient_specs=_passphrase_specs("pp"),
        original_filename="big.wav",
        chunk_size=128 * 1024,  # 8 chunks
    )
    metadata, recovered = package.unpack(blob, passphrase="pp")
    assert metadata.num_chunks == 8
    assert recovered == plaintext


def test_signed_package_roundtrip_and_verification() -> None:
    sk = keys.generate_ed25519_keypair()
    blob = package.pack(
        b"signed content" * 100,
        recipient_specs=_passphrase_specs("pp"),
        original_filename="t.wav",
        signing_key=sk.private_key,
    )
    metadata, _ = package.unpack(
        blob, passphrase="pp", expected_signing_pubkey=sk.public_key
    )
    assert metadata.signature_algorithm == crypto.SIGNATURE_ALGORITHM_NAME


def test_signed_package_unsigned_expected_raises() -> None:
    sk = keys.generate_ed25519_keypair()
    blob = package.pack(
        b"unsigned",
        recipient_specs=_passphrase_specs("pp"),
        original_filename="t.wav",
        # no signing_key
    )
    with pytest.raises(crypto.InvalidSignatureError):
        package.unpack(blob, passphrase="pp", expected_signing_pubkey=sk.public_key)


def test_signed_package_wrong_signer_raises() -> None:
    real = keys.generate_ed25519_keypair()
    other = keys.generate_ed25519_keypair()
    blob = package.pack(
        b"audio",
        recipient_specs=_passphrase_specs("pp"),
        original_filename="t.wav",
        signing_key=real.private_key,
    )
    with pytest.raises(crypto.InvalidSignatureError):
        package.unpack(blob, passphrase="pp", expected_signing_pubkey=other.public_key)
