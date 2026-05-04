# Evaluation Plan (Chapter 5)

This document defines the evaluation strategy for the SecureTrack
prototype. The evaluation is organised around four pillars —
**functional**, **security**, **performance** and **usability** — and
is designed to be reproducible from the test suite and CLI shipped in
this repository.

## 1. Functional testing

The aim is to demonstrate that the prototype performs the operations
described in Chapter 4 (Design) end-to-end without data loss.

| ID  | Requirement                                   | Method                                                       |
|-----|-----------------------------------------------|--------------------------------------------------------------|
| F1  | Encrypt a WAV file from disk                  | `tests/test_crypto_roundtrip.py::test_metadata_round_trip_through_disk` |
| F2  | Decrypt a `.securetrack` package back to WAV  | Same test as F1 — confirms `out.read_bytes() == src.read_bytes()` |
| F3  | Package round-trip in memory                  | `test_encrypt_then_decrypt_returns_exact_plaintext`          |
| F4  | Package metadata captures all required fields | `test_package_contains_required_metadata_fields`             |
| F5  | Two packages of the same file differ          | `test_two_packages_use_different_salt_and_nonce`             |
| F6  | CLI `encrypt`/`decrypt`/`benchmark` succeed   | Manual run from `README.md`, captured in Appendix screenshots |

## 2. Security testing

The security evaluation verifies the three properties claimed by the
design: confidentiality, integrity and authentication.

| ID  | Property              | Method                                                         |
|-----|-----------------------|----------------------------------------------------------------|
| S1  | Wrong passphrase      | `test_wrong_passphrase_raises` — must raise `InvalidPassphraseError` |
| S2  | Single-byte ciphertext mutation | `test_flipping_one_byte_in_ciphertext_fails`           |
| S3  | Truncated package     | `test_truncated_package_fails`                                 |
| S4  | Metadata tampering    | `test_tampering_with_metadata_fails`                           |
| S5  | Garbage ciphertext    | `test_swapping_ciphertext_for_garbage_fails`                   |
| S6  | Non-ZIP input         | `test_non_zip_input_raises_value_error`                        |
| S7  | Salt + nonce uniqueness | `test_two_packages_use_different_salt_and_nonce`             |

Tamper detection is implemented inside `benchmark.run_benchmark` as
well, so every benchmark run also produces a "tamper_detection_passed"
column in the CSV.

## 3. Performance testing

Performance is measured with a single encrypt/decrypt round-trip per
benchmark run. The CLI command

```bash
python -m securetrack.cli benchmark -i <wav> -o results/benchmark_results.csv -p <pp>
```

writes one row to the results CSV with the columns documented in
``technical_design.md``. The dissertation will collect a small matrix
of inputs:

| Input                          | Approx. size | Purpose                              |
|--------------------------------|--------------|--------------------------------------|
| 2 s mono sine 16-bit 44.1 kHz  | ~170 KB      | Smallest realistic stem              |
| 30 s stereo 16-bit 48 kHz      | ~5.5 MB      | Typical loop / vocal take            |
| 4 min stereo 24-bit 48 kHz     | ~70 MB       | Full song bounce                     |
| 10 min stereo 24-bit 48 kHz    | ~170 MB      | Stress / scaling check               |

For each input we report mean and standard deviation across at least
ten runs.

### 3.1 How encryption overhead is measured

For every benchmark row:

* `original_size_bytes` — `Path(input).stat().st_size` of the WAV.
* `encrypted_size_bytes` — `len(package_bytes)` after `package.pack`.
* `size_overhead_bytes`  — `encrypted - original`.
* `size_overhead_percent` — `(encrypted - original) / original * 100`.

The overhead is dominated by the ZIP container, the JSON metadata
header and the 16-byte AES-GCM authentication tag. We expect overhead
to be effectively constant in absolute bytes (under 1 KB) and to
become negligible in percentage terms above a few hundred KB of
audio.

### 3.2 How throughput is measured

`time.perf_counter()` brackets each operation. Throughput in MB/s is
defined as `original_size_bytes / 1_000_000 / elapsed_seconds`.

We report both encryption and decryption throughput separately
because Scrypt key derivation runs once per direction and dominates
short-payload timing, while AES-GCM dominates long-payload timing.

## 4. Correctness via SHA-256 hash comparison

For every benchmark run we compute:

```
sha256_original  = hashlib.sha256(plaintext).hexdigest()
sha256_decrypted = hashlib.sha256(decrypted).hexdigest()
hash_match       = sha256_original == sha256_decrypted
```

`hash_match` must be `true` for every row in the results CSV. Any
`false` row would mean either a bug in the cryptographic round-trip
or accidental in-memory corruption, both of which would invalidate
the prototype.

## 5. Tamper detection methodology

Inside `benchmark.run_benchmark` we:

1. Build a valid package as usual.
2. Flip exactly one byte at offset `-32` (inside the AES-GCM tag
   region — any single-byte mutation anywhere in the file would do
   the job).
3. Attempt to decrypt the modified package and catch
   `InvalidPassphraseError` / `ValueError`.
4. Record `tamper_detection_passed = true` if and only if the
   decryption raised.

In the unit suite (`tests/test_tamper_detection.py`) we additionally
mutate the metadata and replace the entire ciphertext with zeros, to
show that the failure is not specific to the chosen byte offset.

## 6. Usability testing

A small, low-risk usability study is planned for the dissertation:

* **Participants**: 4–6 University of Surrey music students who
  already use Audacity for collaboration.
* **Tasks**: (a) export a WAV from Audacity, (b) encrypt it with a
  passphrase, (c) send the resulting `.securetrack` package to a
  partner, (d) decrypt and re-import into Audacity.
* **Instruments**: a 5-point Likert scale on perceived ease of use
  and perceived security, plus an open question about friction.
* **Ethics**: no audio is collected; only ratings and free-text
  comments. Approval will be obtained via the standard Surrey
  ethics self-assessment form.

The expected outcome is qualitative — identifying friction points
that should drive the next iteration of the GUI rather than
rigorously quantifying productivity gains.

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
