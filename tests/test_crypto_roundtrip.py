"""Tests for round-trip correctness of the SecureTrack crypto / package layer."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from securetrack import crypto, package


def test_encrypt_then_decrypt_returns_exact_plaintext() -> None:
    plaintext = b"the quick brown fox jumps over the lazy dog" * 1000
    blob = package.pack(plaintext, "correct horse battery staple", original_filename="t.wav")
    metadata, recovered = package.unpack(blob, "correct horse battery staple")
    assert recovered == plaintext
    assert metadata.original_filename == "t.wav"
    assert metadata.original_size_bytes == len(plaintext)


def test_random_payload_roundtrip() -> None:
    plaintext = os.urandom(64 * 1024)
    blob = package.pack(plaintext, "another-passphrase!", original_filename="random.bin")
    _, recovered = package.unpack(blob, "another-passphrase!")
    assert recovered == plaintext


def test_wrong_passphrase_raises() -> None:
    blob = package.pack(b"secret bytes", "good-passphrase", original_filename="x.wav")
    with pytest.raises(crypto.InvalidPassphraseError):
        package.unpack(blob, "WRONG-passphrase")


def test_empty_passphrase_rejected_at_encrypt() -> None:
    with pytest.raises(ValueError):
        package.pack(b"data", "", original_filename="x.wav")


def test_metadata_round_trip_through_disk(tmp_path: Path) -> None:
    src = tmp_path / "in.wav"
    src.write_bytes(b"riff-style payload" * 100)
    pkg = tmp_path / "out.securetrack"
    out = tmp_path / "recovered.wav"

    written_meta = package.encrypt_file(src, pkg, "pass-1234", labels={"project": "demo"})
    read_meta = package.decrypt_file(pkg, out, "pass-1234")

    assert out.read_bytes() == src.read_bytes()
    assert written_meta.original_filename == "in.wav"
    assert read_meta.labels == {"project": "demo"}


def test_package_contains_required_metadata_fields() -> None:
    plaintext = b"hello world"
    blob = package.pack(plaintext, "pp", original_filename="hello.wav")
    metadata, _ = package.unpack(blob, "pp")
    assert metadata.algorithm == crypto.ALGORITHM_NAME
    assert metadata.kdf == crypto.KDF_NAME
    assert metadata.format_version == package.PACKAGE_FORMAT_VERSION
    assert len(metadata.salt) == crypto.SALT_LENGTH
    assert len(metadata.nonce) == crypto.NONCE_LENGTH
    assert metadata.sha256_original == package.sha256_hex(plaintext)
    assert metadata.created_utc.endswith("Z")


def test_two_packages_use_different_salt_and_nonce() -> None:
    a, _ = package.unpack(package.pack(b"x", "p", original_filename="a"), "p")
    b, _ = package.unpack(package.pack(b"x", "p", original_filename="a"), "p")
    assert a.salt != b.salt
    assert a.nonce != b.nonce
