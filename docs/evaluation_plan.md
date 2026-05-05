# Evaluation Plan (Chapter 5) — v2

This document defines the evaluation strategy for the v2 SecureTrack
prototype. The evaluation is organised around four pillars —
**functional**, **security**, **performance** and **usability** — and
is designed to be reproducible from the test suite and CLI shipped in
this repository.

## 1. Functional testing

| ID  | Requirement                                          | Method                                                       |
|-----|------------------------------------------------------|--------------------------------------------------------------|
| F1  | Encrypt then decrypt with a passphrase recipient     | `tests/test_crypto_roundtrip.py::test_encrypt_then_decrypt_returns_exact_plaintext` |
| F2  | Encrypt then decrypt with an X25519 pubkey recipient | `test_pubkey_roundtrip`                                      |
| F3  | Mixed recipients: either credential works            | `test_multi_recipient_either_works`                          |
| F4  | Optional Ed25519 signature verifies                  | `test_signed_package_roundtrip_and_verification`             |
| F5  | Chunked streaming for multi-MiB payloads             | `test_chunked_streaming_for_multi_chunk_payload`             |
| F6  | Metadata captures every required field               | `test_package_contains_required_metadata_fields`             |
| F7  | CLI `keygen`/`encrypt`/`decrypt`/`inspect` succeed   | `tests/test_cli.py` (5 tests)                                |
| F8  | Audacity bridge drives `Help` and `Export2` against a fake pipe | `tests/test_audacity_bridge.py`                    |

## 2. Security testing

| ID   | Property                              | Method                                                       |
|------|---------------------------------------|--------------------------------------------------------------|
| S1   | Wrong passphrase                      | `test_wrong_passphrase_raises`                               |
| S2   | Wrong X25519 private key              | `test_pubkey_wrong_private_key_fails`                        |
| S3   | Single-byte ciphertext mutation       | `test_flipping_one_byte_in_ciphertext_fails`                 |
| S4   | Truncated package                     | `test_truncated_package_fails`                               |
| S5   | Tampered metadata                     | `test_tampering_with_metadata_fails`, `test_tampering_with_metadata_byte_in_middle_fails` |
| S6   | Tampered recipients list              | `test_tampering_with_recipients_fails`                       |
| S7   | Garbage ciphertext                    | `test_swapping_ciphertext_for_garbage_fails`                 |
| S8   | Non-ZIP input                         | `test_non_zip_input_raises_value_error`                      |
| S9   | Chunk reorder                         | `tests/test_streaming.py::test_streaming_rejects_chunk_reorder` |
| S10  | Chunk truncation                      | `test_streaming_rejects_truncation`                          |
| S11  | AAD mismatch                          | `test_streaming_rejects_wrong_aad`                           |
| S12  | Signature: missing when expected      | `test_signed_package_unsigned_expected_raises`               |
| S13  | Signature: signed by the wrong key    | `test_signed_package_wrong_signer_raises`                    |
| S14  | Signature: detects 1-byte ciphertext flip | `test_signature_tamper_detected_when_one_ciphertext_byte_flipped` |
| S15  | Per-package nonce prefix uniqueness   | `test_two_packages_use_different_nonce_prefix`               |
| S16  | At-rest passphrase protection of private keys | `test_x25519_private_key_is_passphrase_protected`    |

Tamper detection is also re-verified inside `benchmark.run_benchmark`,
so every benchmark run produces a `tamper_detection_passed` column.

## 3. Performance testing

Performance is measured with a single encrypt/decrypt round-trip per
benchmark run:

```bash
python -m securetrack.cli benchmark -i <wav> -o results/benchmark_results.csv -p <pp>
```

The CLI writes one row per invocation. The dissertation will collect
a small matrix of inputs:

| Input                          | Approx. size | Purpose                              |
|--------------------------------|--------------|--------------------------------------|
| 2 s mono sine 16-bit 44.1 kHz  | ~170 KB      | Smallest realistic stem              |
| 30 s stereo 16-bit 48 kHz      | ~5.5 MB      | Typical loop / vocal take            |
| 4 min stereo 24-bit 48 kHz     | ~70 MB       | Full song bounce                     |
| 10 min stereo 24-bit 48 kHz    | ~170 MB      | Stress / scaling check               |

For each input we report mean and standard deviation across at least
ten runs, separately for:

* **passphrase recipient** (Scrypt-dominated cost);
* **single X25519 recipient** (essentially raw AES-GCM cost, no
  Scrypt at all);
* **passphrase + X25519 recipient** (the slowest case, both KDFs);
* **signed package** (adds one Ed25519 sign / verify, ~microseconds).

### 3.1 How encryption overhead is measured

For every benchmark row:

* `original_size_bytes` — `Path(input).stat().st_size` of the WAV.
* `encrypted_size_bytes` — `len(package_bytes)` after `package.pack`.
* `size_overhead_bytes`  — `encrypted - original`.
* `size_overhead_percent` — `(encrypted - original) / original * 100`.

The overhead now scales weakly with the number of recipients (each
recipient entry adds ~250 bytes) and with the number of chunks
(16 bytes per chunk). For a 5 MB WAV, default chunk size, one
passphrase recipient, no signature: about 0.02 % overhead.

### 3.2 How throughput is measured

`time.perf_counter()` brackets each operation. Throughput in MB/s is
defined as `original_size_bytes / 1_000_000 / elapsed_seconds`. We
report encryption and decryption throughput separately because
Scrypt key derivation runs once per direction (only for passphrase
recipients) and dominates short-payload timing, while AES-GCM
dominates long-payload timing.

## 4. Correctness via SHA-256 hash comparison

For every benchmark run we compute:

```
sha256_original  = hashlib.sha256(plaintext).hexdigest()
sha256_decrypted = hashlib.sha256(decrypted).hexdigest()
hash_match       = sha256_original == sha256_decrypted
```

`hash_match` must be `true` for every row in the results CSV. Any
`false` row would mean a bug in the cryptographic round-trip and
would invalidate the prototype.

## 5. Tamper detection methodology

Inside `benchmark.run_benchmark` we:

1. Build a valid package with a passphrase recipient.
2. Flip exactly one byte at offset `-32` (inside the AES-GCM tag
   region of the last chunk).
3. Attempt to decrypt and catch `InvalidPassphraseError` /
   `ValueError`.
4. Record `tamper_detection_passed = true` if and only if the
   decryption raised.

In the unit suite (`tests/test_tamper_detection.py`,
`tests/test_streaming.py`) we additionally:

* mutate the metadata,
* replace the entire ciphertext with zeros,
* reorder chunks,
* truncate chunks,
* tamper with the recipients list,
* and (when signed) flip a ciphertext byte and confirm the signature
  catches it.

## 6. Usability testing

A small low-risk usability study is planned for the dissertation:

* **Participants**: 4–6 University of Surrey music students who
  already use Audacity for collaboration.
* **Tasks**:
  1. Generate an X25519 keypair via the GUI keygen (CLI fallback).
  2. Receive a partner's public key via Slack/email.
  3. Encrypt an exported WAV to that public key.
  4. Send the resulting `.securetrack` package.
  5. Decrypt a package received from a partner and import it into
     Audacity.
* **Instruments**: a 5-point Likert scale on perceived ease of use
  and perceived security, plus an open question about friction.
* **Ethics**: no audio is collected; only ratings and free-text
  comments. Approval will be obtained via the standard Surrey
  ethics self-assessment form.

## 7. Reporting table (template for Chapter 5)

| Metric                      | Unit | 170 KB | 5.5 MB | 70 MB | 170 MB |
|-----------------------------|------|--------|--------|-------|--------|
| Original size               | B    |        |        |       |        |
| Encrypted size              | B    |        |        |       |        |
| Size overhead               | B    |        |        |       |        |
| Size overhead               | %    |        |        |       |        |
| Encryption time             | s    |        |        |       |        |
| Decryption time             | s    |        |        |       |        |
| Encryption throughput       | MB/s |        |        |       |        |
| Decryption throughput       | MB/s |        |        |       |        |
| Hash match                  | bool |        |        |       |        |
| Tamper detection passed     | bool |        |        |       |        |

Cells will be filled from `results/benchmark_results.csv` and
plotted with `matplotlib` once enough data has been collected.
