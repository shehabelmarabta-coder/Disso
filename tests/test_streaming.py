"""Tests for chunked streaming AEAD primitives."""

from __future__ import annotations

import os

import pytest

from securetrack import crypto


def _aad() -> bytes:
    return b"test-aad-for-streaming"


@pytest.mark.parametrize(
    "size,chunk_size",
    [
        (0, 1024),                # empty file -> 1 empty chunk
        (1, 1024),                # one tiny chunk
        (1024, 1024),             # exactly one full chunk
        (1024 + 1, 1024),         # two chunks, second tiny
        (5 * 1024, 1024),         # five full chunks
        (5 * 1024 + 7, 1024),     # six chunks, last short
        (256 * 1024, 64 * 1024),  # 4 chunks of 64 KiB
    ],
)
def test_streaming_roundtrip(size: int, chunk_size: int) -> None:
    plaintext = os.urandom(size)
    content_key = crypto.generate_content_key()
    nonce_prefix = crypto.generate_nonce_prefix()
    aad = _aad()

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


def test_streaming_rejects_chunk_reorder() -> None:
    plaintext = b"chunk0_chunk1_chunk2_"
    content_key = crypto.generate_content_key()
    nonce_prefix = crypto.generate_nonce_prefix()
    aad = _aad()
    chunks = crypto.split_into_chunks(plaintext, 7)
    cts = list(
        crypto.encrypt_chunks(
            chunks, content_key=content_key, nonce_prefix=nonce_prefix, base_aad=aad
        )
    )
    # Swap the order of the first two chunks - same total bytes, but
    # AAD authenticates the chunk index, so decryption must fail.
    swapped = cts[1] + cts[0] + cts[2]
    with pytest.raises(crypto.InvalidPassphraseError):
        crypto.decrypt_chunks(
            swapped,
            content_key=content_key,
            nonce_prefix=nonce_prefix,
            base_aad=aad,
            chunk_size=7,
            num_chunks=3,
            plaintext_size=len(plaintext),
        )


def test_streaming_rejects_truncation() -> None:
    plaintext = b"abcdefghij" * 1024
    content_key = crypto.generate_content_key()
    nonce_prefix = crypto.generate_nonce_prefix()
    aad = _aad()
    chunks = crypto.split_into_chunks(plaintext, 1024)
    ciphertext = b"".join(
        crypto.encrypt_chunks(
            chunks, content_key=content_key, nonce_prefix=nonce_prefix, base_aad=aad
        )
    )
    with pytest.raises(crypto.InvalidPassphraseError):
        crypto.decrypt_chunks(
            ciphertext[:-50],  # truncate
            content_key=content_key,
            nonce_prefix=nonce_prefix,
            base_aad=aad,
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
