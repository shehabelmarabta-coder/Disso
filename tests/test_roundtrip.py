"""Round-trip correctness tests.

Verifies that encrypting an audio file and then decrypting the
resulting ``.securetrack`` package returns exactly the original
bytes, across the full set of supported recipient and signing
modes (passphrase, X25519 public key, mixed, signed).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from securetrack import crypto, keys, package, recipients


def _passphrase_specs(pp: str = "correct horse battery staple") -> list[recipients.RecipientSpec]:
    return [recipients.PassphraseRecipient(passphrase=pp)]


# --- in-memory round-trips -------------------------------------------------


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


def test_random_payload_roundtrip() -> None:
    plaintext = os.urandom(64 * 1024)
    blob = package.pack(
        plaintext,
        recipient_specs=_passphrase_specs("another-passphrase!"),
        original_filename="random.bin",
    )
    _, recovered = package.unpack(blob, passphrase="another-passphrase!")
    assert recovered == plaintext


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


def test_multi_recipient_either_works() -> None:
    kp = keys.generate_x25519_keypair()
    plaintext = b"shared content"
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


def test_signed_package_roundtrip() -> None:
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


# --- on-disk round-trips ---------------------------------------------------


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


# --- metadata sanity -------------------------------------------------------


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


# --- key (PEM) round-trips -------------------------------------------------


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
    # Same shared secret means same key material.
    shared_a = loaded_priv.exchange(kp.public_key)
    shared_b = kp.private_key.exchange(loaded_pub)
    assert shared_a == shared_b


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


# --- per-recipient wrapping round-trips -----------------------------------


def test_passphrase_wrap_unwrap_roundtrip() -> None:
    content_key = os.urandom(crypto.KEY_LENGTH)
    aad = b"metadata"
    entry = recipients.wrap_for_passphrase(content_key, "pp", aad=aad, label="alice")
    unwrapped = recipients.unwrap_with_passphrase(entry, "pp", aad=aad)
    assert unwrapped == content_key
    assert entry.label == "alice"


def test_pubkey_wrap_unwrap_roundtrip() -> None:
    kp = keys.generate_x25519_keypair()
    content_key = os.urandom(crypto.KEY_LENGTH)
    entry = recipients.wrap_for_pubkey(content_key, kp.public_key, aad=b"a")
    unwrapped = recipients.unwrap_with_private_key(entry, kp.private_key, aad=b"a")
    assert unwrapped == content_key


def test_unwrap_content_key_with_either_credential() -> None:
    """Pubkey wraps are tried first because they are cheap; passphrase
    wraps fall back when only a passphrase is supplied."""
    kp = keys.generate_x25519_keypair()
    content_key = os.urandom(crypto.KEY_LENGTH)
    entries = [
        recipients.wrap_for_passphrase(content_key, "pp", aad=b"a"),
        recipients.wrap_for_pubkey(content_key, kp.public_key, aad=b"a"),
    ]
    by_pubkey = recipients.unwrap_content_key(
        entries, aad=b"a", passphrase="pp", private_key=kp.private_key
    )
    by_passphrase = recipients.unwrap_content_key(
        entries, aad=b"a", passphrase="pp"
    )
    assert by_pubkey == content_key == by_passphrase


def test_wrapped_recipient_json_roundtrip() -> None:
    kp = keys.generate_x25519_keypair()
    entry = recipients.wrap_for_pubkey(os.urandom(32), kp.public_key, aad=b"a", label="x")
    rebuilt = recipients.WrappedRecipient.from_json_obj(entry.to_json_obj())
    assert rebuilt.type == entry.type
    assert rebuilt.kind == entry.kind
    assert rebuilt.wrap_nonce == entry.wrap_nonce
    assert rebuilt.wrapped_key == entry.wrapped_key
    assert rebuilt.recipient_pubkey == entry.recipient_pubkey
    assert rebuilt.ephemeral_pubkey == entry.ephemeral_pubkey
    assert rebuilt.label == "x"


# --- chunked streaming round-trip -----------------------------------------


@pytest.mark.parametrize(
    "size,chunk_size",
    [
        (0, 1024),
        (1, 1024),
        (1024, 1024),
        (1024 + 1, 1024),
        (5 * 1024, 1024),
        (5 * 1024 + 7, 1024),
        (256 * 1024, 64 * 1024),
    ],
)
def test_streaming_roundtrip(size: int, chunk_size: int) -> None:
    plaintext = os.urandom(size)
    content_key = crypto.generate_content_key()
    nonce_prefix = crypto.generate_nonce_prefix()
    aad = b"test-aad"

    chunks = crypto.split_into_chunks(plaintext, chunk_size)
    ciphertext = b"".join(
        crypto.encrypt_chunks(
            chunks, content_key=content_key, nonce_prefix=nonce_prefix, base_aad=aad
        )
    )
    recovered = crypto.decrypt_chunks(
        ciphertext,
        content_key=content_key,
        nonce_prefix=nonce_prefix,
        base_aad=aad,
        chunk_size=chunk_size,
        num_chunks=len(chunks),
        plaintext_size=size,
    )
    assert recovered == plaintext


def test_chunked_streaming_records_num_chunks() -> None:
    plaintext = bytes(range(256)) * 4096  # exactly 1 MiB
    blob = package.pack(
        plaintext,
        recipient_specs=_passphrase_specs("pp"),
        original_filename="big.wav",
        chunk_size=128 * 1024,  # 8 chunks
    )
    metadata, recovered = package.unpack(blob, passphrase="pp")
    assert metadata.num_chunks == 8
    assert recovered == plaintext
