"""Tests for X25519 / Ed25519 keypair generation and PEM I/O."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from securetrack import keys


def test_x25519_keypair_generation_unique() -> None:
    a = keys.generate_x25519_keypair()
    b = keys.generate_x25519_keypair()
    assert keys.x25519_public_bytes(a.public_key) != keys.x25519_public_bytes(b.public_key)
    assert len(keys.x25519_public_bytes(a.public_key)) == 32


def test_ed25519_keypair_generation_unique() -> None:
    a = keys.generate_ed25519_keypair()
    b = keys.generate_ed25519_keypair()
    assert keys.ed25519_public_bytes(a.public_key) != keys.ed25519_public_bytes(b.public_key)
    assert len(keys.ed25519_public_bytes(a.public_key)) == 32


def test_x25519_pem_roundtrip(tmp_path: Path) -> None:
    kp = keys.generate_x25519_keypair()
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    keys.write_keypair(kp, private_path=priv, public_path=pub)
    assert priv.exists() and pub.exists()
    assert b"BEGIN PRIVATE KEY" in priv.read_bytes()
    assert b"BEGIN PUBLIC KEY" in pub.read_bytes()

    loaded_priv = keys.load_x25519_private(priv)
    loaded_pub = keys.load_x25519_public(pub)
    # X25519 doesn't expose raw public bytes the same way for comparison;
    # use Diffie-Hellman: same shared secret == same key material.
    shared_a = loaded_priv.exchange(kp.public_key)
    shared_b = kp.private_key.exchange(loaded_pub)
    assert shared_a == shared_b


def test_x25519_private_key_is_passphrase_protected(tmp_path: Path) -> None:
    kp = keys.generate_x25519_keypair()
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    keys.write_keypair(kp, private_path=priv, public_path=pub, passphrase="hunter2")
    # No passphrase should fail.
    with pytest.raises(Exception):
        keys.load_x25519_private(priv)
    # Wrong passphrase should fail.
    with pytest.raises(Exception):
        keys.load_x25519_private(priv, passphrase="wrong")
    # Correct passphrase should succeed.
    loaded = keys.load_x25519_private(priv, passphrase="hunter2")
    shared = loaded.exchange(kp.public_key)
    assert isinstance(shared, bytes) and len(shared) == 32


def test_ed25519_pem_roundtrip(tmp_path: Path) -> None:
    kp = keys.generate_ed25519_keypair()
    priv = tmp_path / "sign.pem"
    pub = tmp_path / "verify.pem"
    keys.write_keypair(kp, private_path=priv, public_path=pub)
    loaded_priv = keys.load_ed25519_private(priv)
    loaded_pub = keys.load_ed25519_public(pub)

    msg = os.urandom(64)
    sig = loaded_priv.sign(msg)
    loaded_pub.verify(sig, msg)
    # Round-trip through raw bytes too.
    raw = keys.ed25519_public_bytes(kp.public_key)
    keys.ed25519_public_from_bytes(raw).verify(sig, msg)


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
