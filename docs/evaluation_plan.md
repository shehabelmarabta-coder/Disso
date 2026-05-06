# Evaluation Plan

This document supports Chapter 5 of the dissertation. The evaluation
is organised around four pillars — **functional**, **security**,
**performance**, **usability** — and is designed to be reproducible
from the test suite and CLI shipped in this repository.

## 1. Functional testing

The aim is to demonstrate that the prototype performs the operations
described in Chapter 4 end-to-end without data loss.

| ID  | Requirement                                                          | Method                                                       |
|-----|----------------------------------------------------------------------|--------------------------------------------------------------|
| F1  | Encrypt then decrypt with a passphrase recipient                     | ``tests/test_roundtrip.py::test_encrypt_then_decrypt_returns_exact_plaintext`` |
| F2  | Encrypt then decrypt with an X25519 public-key recipient             | ``test_pubkey_roundtrip``                                    |
| F3  | Mixed recipients: either credential works                            | ``test_multi_recipient_either_works``                        |
| F4  | Optional Ed25519 signature verifies                                  | ``test_signed_package_roundtrip``                            |
| F5  | Round-trip on disk preserves the original bytes                      | ``test_metadata_round_trip_through_disk``                    |
| F6  | Metadata captures every required field                               | ``test_package_contains_required_metadata_fields``           |
| F7  | CLI ``keygen``/``encrypt``/``decrypt``/``inspect`` succeed           | ``tests/test_cli.py``                                        |
| F8  | Audacity bridge sends ``SelectAll`` then ``Export2``                  | ``tests/test_audacity_bridge.py::test_export_wav_sends_select_all_and_export2`` |
| F9  | Audacity bridge rejects an empty exported WAV                         | ``test_export_wav_rejects_empty_export``                     |
| F10 | Watcher encrypts a new WAV dropped into Exports                      | ``tests/test_watch_folder.py::test_watcher_encrypts_new_wav`` |
| F11 | Watcher does not re-encrypt a stable file                            | ``test_watcher_does_not_re_encrypt_stable_file``             |
| F12 | Watcher keeps / moves / deletes the source per setting               | ``test_watcher_keeps_source_by_default``, ``test_watcher_moves_source_to_archive``, ``test_watcher_deletes_source_when_requested`` |
| F13 | Watched-folder package decrypts back to the original bytes           | covered inside ``test_watcher_encrypts_new_wav``              |
| F14 | Recovered WAV imports into Audacity                                  | manual evaluation step with screenshot evidence              |

## 2. Security testing

| ID   | Property                              | Method                                                       |
|------|---------------------------------------|--------------------------------------------------------------|
| S1   | Wrong passphrase                      | ``tests/test_security.py::test_wrong_passphrase_raises``     |
| S2   | Wrong X25519 private key              | ``test_pubkey_wrong_private_key_fails``                      |
| S3   | Single-byte ciphertext mutation       | ``test_flipping_one_byte_in_ciphertext_fails``               |
| S4   | Truncated package                     | ``test_truncated_package_fails``                             |
| S5   | Tampered metadata                     | ``test_tampering_with_metadata_fails`` and ``test_tampering_with_metadata_byte_in_middle_fails`` |
| S6   | Tampered recipients list              | ``test_tampering_with_recipients_fails``                     |
| S7   | Garbage ciphertext                    | ``test_swapping_ciphertext_for_garbage_fails``               |
| S8   | Non-ZIP input                         | ``test_non_zip_input_raises_value_error``                    |
| S9   | Chunk reorder                         | ``test_streaming_rejects_chunk_reorder``                     |
| S10  | Chunk truncation                      | ``test_streaming_rejects_truncation``                        |
| S11  | Associated-data mismatch              | ``test_streaming_rejects_wrong_aad``                         |
| S12  | Signature: missing when expected      | ``test_signed_package_unsigned_expected_raises``             |
| S13  | Signature: signed by the wrong key    | ``test_signed_package_wrong_signer_raises``                  |
| S14  | Signature detects 1-byte ciphertext flip | ``test_signature_detects_one_byte_ciphertext_flip``       |
| S15  | At-rest passphrase protection of private keys | ``test_x25519_private_key_is_passphrase_protected``  |
| S16  | Private key file mode 0o600 on POSIX  | ``test_private_key_file_mode_is_600_on_posix``               |
| S17  | Per-package nonce-prefix uniqueness   | ``test_two_packages_use_different_nonce_prefix``             |

Tamper detection is also re-verified inside ``benchmark.run_benchmark``,
so every benchmark run records a ``tamper_detection_passed`` column.

## 3. Performance testing

Performance is measured with a single encrypt/decrypt round-trip per
benchmark run:

```
python -m securetrack.cli benchmark -i <wav> -o results/benchmark_results.csv -p <passphrase>
```

The dissertation collects results across a small matrix of inputs:

| Input                          | Approx. size | Purpose                              |
|--------------------------------|--------------|--------------------------------------|
| 2 s mono sine 16-bit 44.1 kHz  | ~170 KB      | Smallest realistic stem              |
| 30 s stereo 16-bit 48 kHz      | ~5.5 MB      | Typical loop or vocal take           |
| 4 min stereo 24-bit 48 kHz     | ~70 MB       | Full song bounce                     |
| 10 min stereo 24-bit 48 kHz    | ~170 MB      | Stress / scaling check               |

Each input is run at least ten times; mean and standard deviation
are reported.

### 3.1 Encryption overhead

For every benchmark row the application records:

* ``original_size_bytes`` — ``Path(input).stat().st_size``.
* ``encrypted_size_bytes`` — ``len(package_bytes)`` after sealing.
* ``size_overhead_bytes``  — ``encrypted - original``.
* ``size_overhead_percent`` — ``(encrypted - original) / original * 100``.

### 3.2 Throughput

``time.perf_counter()`` brackets each operation. Throughput in MB/s
is defined as ``original_size_bytes / 1_000_000 / elapsed_seconds``.
Encryption and decryption are reported separately.

## 4. Correctness via SHA-256 hash comparison

For every benchmark row:

```
sha256_original  = hashlib.sha256(plaintext).hexdigest()
sha256_decrypted = hashlib.sha256(decrypted).hexdigest()
hash_match       = sha256_original == sha256_decrypted
```

``hash_match`` must be ``true`` for every row.

## 5. Tamper detection methodology

Inside ``benchmark.run_benchmark``:

1. Build a valid package.
2. Flip exactly one byte at offset ``-32`` (inside the AES-GCM tag
   region of the last chunk).
3. Attempt to decrypt and catch the resulting error.
4. Record ``tamper_detection_passed = true`` if and only if
   decryption raised.

The unit suite (``tests/test_security.py``) additionally mutates
the metadata, swaps the entire ciphertext for zeros, reorders and
truncates chunks, and tampers with the recipients list. The
optional signature is verified separately via
``test_signature_detects_one_byte_ciphertext_flip``.

## 6. Usability testing

A small low-risk usability study is planned for the dissertation:

* **Participants.** 4–6 University of Surrey music students who
  already use Audacity for collaboration.
* **Tasks.**
  1. Open SecureTrack and click *Create / Open SecureTrack
     Folders* on the Audacity Workflow tab.
  2. Start watching the Exports folder.
  3. Open Audacity, work on a small project, *Export* a WAV into
     ``Documents/SecureTrack/Exports``.
  4. Confirm a ``.securetrack`` package appears in
     ``Documents/SecureTrack/Secure Packages`` automatically.
  5. (Optional) Use *Option B — Export directly from Audacity* to
     export the same project through ``mod-script-pipe``.
  6. Decrypt a package received from a partner and import the
     recovered WAV into Audacity.
* **Step counting.** Number of distinct user actions in the
  *Recommended Audacity Workflow* — used as a coarse usability
  metric ("how many clicks does this take?").
* **Instruments.** A 5-point Likert scale on perceived ease of use
  and perceived security, plus an open question about friction.
* **Ethics.** No audio is collected; only ratings and free-text
  comments. Approval is obtained via the standard Surrey ethics
  self-assessment form.

## 7. Test evidence checklist

The dissertation appendix should include screenshots of:

* [ ] SecureTrack GUI window with the **Audacity Workflow** tab
      visible (workspace + recipient + watcher controls + activity
      log).
* [ ] Workspace folders opened in the OS file manager
      (``Documents/SecureTrack/Exports`` and ``Secure Packages``).
* [ ] *Watching …* status with a freshly encrypted entry in the
      activity log.
* [ ] An exported WAV in ``Exports/`` and the matching
      ``.securetrack`` package in ``Secure Packages/``.
* [ ] Decryption success dialog showing the recovered file.
* [ ] Decryption failure dialog after a wrong passphrase.
* [ ] Audacity *Test Audacity Connection* result (success).
* [ ] Audacity *Export from Audacity and Encrypt* success dialog.
* [ ] The recovered WAV imported into Audacity (track visible in
      the Audacity timeline).
* [ ] Benchmark CSV opened in a spreadsheet, with at least one row
      per input from the size matrix.
* [ ] ``pytest -v`` console output showing every test passing.
* [ ] (Optional) ``securetrack inspect --json`` output for a
      package.

## 8. Benchmark metrics

Every benchmark CSV row contains the following columns. The schema
is fixed by ``securetrack.metrics.CSV_FIELDNAMES``:

| Column                       | Unit / type | Source                                                |
|------------------------------|-------------|-------------------------------------------------------|
| ``timestamp``                | ISO-8601 UTC| Benchmark run start time                              |
| ``input_file``               | path        | The WAV used                                          |
| ``original_size_bytes``      | bytes       | ``Path(input).stat().st_size``                        |
| ``encrypted_size_bytes``     | bytes       | ``len(package_bytes)``                                |
| ``size_overhead_bytes``      | bytes       | ``encrypted - original``                              |
| ``size_overhead_percent``    | %           | ``(encrypted - original) / original * 100``           |
| ``encryption_time_seconds``  | seconds     | ``time.perf_counter()`` brackets the encrypt call     |
| ``decryption_time_seconds``  | seconds     | ``time.perf_counter()`` brackets the decrypt call     |
| ``encryption_throughput_MBps`` | MB/s      | ``original_size_bytes / 1_000_000 / encryption_time`` |
| ``decryption_throughput_MBps`` | MB/s      | ``original_size_bytes / 1_000_000 / decryption_time`` |
| ``sha256_original``          | hex 64      | SHA-256 of the original WAV                           |
| ``sha256_decrypted``         | hex 64      | SHA-256 of the recovered WAV                          |
| ``hash_match``               | bool        | ``sha256_original == sha256_decrypted``               |
| ``tamper_detection_passed``  | bool        | One-byte mutation rejected                            |
| ``algorithm``                | string      | Always ``AES-256-GCM``                                |
| ``kdf``                      | string      | Always ``scrypt`` for the passphrase recipient        |

## 9. Reporting table (Chapter 5 template)

| Metric                     | Unit | 170 KB | 5.5 MB | 70 MB | 170 MB |
|----------------------------|------|--------|--------|-------|--------|
| Original size              | B    |        |        |       |        |
| Encrypted size             | B    |        |        |       |        |
| Size overhead              | B    |        |        |       |        |
| Size overhead              | %    |        |        |       |        |
| Encryption time            | s    |        |        |       |        |
| Decryption time            | s    |        |        |       |        |
| Encryption throughput      | MB/s |        |        |       |        |
| Decryption throughput      | MB/s |        |        |       |        |
| Hash match                 | bool |        |        |       |        |
| Tamper detection passed    | bool |        |        |       |        |

Cells are filled directly from ``results/benchmark_results.csv``.
