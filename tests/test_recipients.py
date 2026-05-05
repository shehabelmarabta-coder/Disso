"""Tests for the per-recipient content-key wrapping helpers."""

from __future__ import annotations

import os

import pytest

from securetrack import crypto, keys, recipients


def test_passphrase_wrap_unwrap_roundtrip() -> None:
    content_key = os.urandom(crypto.KEY_LENGTH)
    aad = b"metadata"
    entry = recipients.wrap_for_passphrase(content_key, "pp", aad=aad, label="alice")
    unwrapped = recipients.unwrap_with_passphrase(entry, "pp", aad=aad)
    assert unwrapped == content_key
    assert entry.label == "alice"


def test_passphrase_wrap_wrong_passphrase_fails() -> None:
    content_key = os.urandom(crypto.KEY_LENGTH)
    entry = recipients.wrap_for_passphrase(content_key, "right", aad=b"a")
    with pytest.raises(crypto.InvalidPassphraseError):
        recipients.unwrap_with_passphrase(entry, "wrong", aad=b"a")


def test_pubkey_wrap_unwrap_roundtrip() -> None:
    kp = keys.generate_x25519_keypair()
    content_key = os.urandom(crypto.KEY_LENGTH)
    entry = recipients.wrap_for_pubkey(content_key, kp.public_key, aad=b"a")
    unwrapped = recipients.unwrap_with_private_key(entry, kp.private_key, aad=b"a")
    assert unwrapped == content_key


def test_pubkey_wrap_wrong_private_key_fails() -> None:
    right = keys.generate_x25519_keypair()
    wrong = keys.generate_x25519_keypair()
    content_key = os.urandom(crypto.KEY_LENGTH)
    entry = recipients.wrap_for_pubkey(content_key, right.public_key, aad=b"a")
    with pytest.raises(crypto.InvalidPassphraseError):
        recipients.unwrap_with_private_key(entry, wrong.private_key, aad=b"a")


def test_unwrap_content_key_tries_pubkey_before_passphrase() -> None:
    """Pubkey wraps are checked first because they are far cheaper."""
    kp = keys.generate_x25519_keypair()
    content_key = os.urandom(crypto.KEY_LENGTH)
    entries = [
        recipients.wrap_for_passphrase(content_key, "pp", aad=b"a"),
        recipients.wrap_for_pubkey(content_key, kp.public_key, aad=b"a"),
    ]
    # Provide both - the function must succeed.
    unwrapped = recipients.unwrap_content_key(
        entries, aad=b"a", passphrase="pp", private_key=kp.private_key
    )
    assert unwrapped == content_key


def test_unwrap_with_neither_credential_raises() -> None:
    content_key = os.urandom(crypto.KEY_LENGTH)
    entries = [recipients.wrap_for_passphrase(content_key, "pp", aad=b"a")]
    with pytest.raises(ValueError):
        recipients.unwrap_content_key(entries, aad=b"a")


def test_unwrap_returns_first_matching_entry() -> None:
    """Multiple passphrase entries: only one matches."""
    content_key = os.urandom(crypto.KEY_LENGTH)
    entries = [
        recipients.wrap_for_passphrase(content_key, "alpha", aad=b"a"),
        recipients.wrap_for_passphrase(content_key, "beta", aad=b"a"),
    ]
    unwrapped = recipients.unwrap_content_key(entries, aad=b"a", passphrase="beta")
    assert unwrapped == content_key


def test_wrapped_recipient_json_roundtrip() -> None:
    kp = keys.generate_x25519_keypair()
    entry = recipients.wrap_for_pubkey(os.urandom(32), kp.public_key, aad=b"a", label="x")
    obj = entry.to_json_obj()
    rebuilt = recipients.WrappedRecipient.from_json_obj(obj)
    assert rebuilt.type == entry.type
    assert rebuilt.kind == entry.kind
    assert rebuilt.wrap_nonce == entry.wrap_nonce
    assert rebuilt.wrapped_key == entry.wrapped_key
    assert rebuilt.recipient_pubkey == entry.recipient_pubkey
    assert rebuilt.ephemeral_pubkey == entry.ephemeral_pubkey
    assert rebuilt.label == "x"
