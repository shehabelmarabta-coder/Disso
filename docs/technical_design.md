# Technical Design

This document is an extended companion to Chapter 4 of the
dissertation. It describes the cryptographic choices, package format
and module layout of the SecureTrack prototype.

## 1. Goals and non-goals

**Goals.**
* End-to-end confidentiality and integrity of an audio file shared
  between two collaborators who already share a passphrase.
* Reproducible measurements for the dissertation evaluation chapter.
* A code base small enough for a single student to explain in the
  dissertation viva.

**Non-goals (this version).**
* Cloud upload, key servers or directory services.
* Per-recipient public-key encryption.
* Native Audacity plug-in / DAW UI integration.
* Streaming I/O for files larger than free RAM.
* Forward secrecy or post-compromise security.

## 2. Cryptographic design

| Concern               | Choice                  | Rationale                                                |
|-----------------------|-------------------------|----------------------------------------------------------|
| Symmetric primitive   | **AES-256-GCM**         | Authenticated encryption in a single primitive; widely audited; available in `cryptography.hazmat.primitives.ciphers.aead`. |
| Key derivation        | **Scrypt** (n=2^15, r=8, p=1, len=32) | Memory-hard, OWASP-recommended for password-derived keys; resists GPU/ASIC brute force. |
| Salt                  | 16 random bytes (`os.urandom`) | Standard length; per-package, never reused.        |
| Nonce                 | 12 random bytes         | 96 bits is the GCM standard. Generated per-package; the GCM uniqueness requirement is satisfied because each package gets a fresh key as well. |
| Random source         | `os.urandom` / `secrets`| OS-provided CSPRNG.                                      |
| Associated data       | The canonical metadata JSON | Binds metadata to the ciphertext. Modifying any metadata field invalidates the GCM tag. |

### 2.1 Why AES-GCM and not ChaCha20-Poly1305?

GCM was chosen for the prototype because (a) it is the format students
encounter in standard cryptography courses, (b) it is hardware
accelerated on every machine the dissertation will run on, and (c) the
nonce/key handling is straightforward when packages are produced one at
a time. ChaCha20-Poly1305 is a perfectly good alternative and could be
swapped in by changing one import.

### 2.2 Why a passphrase, not a key file?

For a first prototype a passphrase is the lowest-friction way to test
the whole pipeline. The dissertation explicitly identifies the move to
per-recipient X25519 public keys as the most important next step.

## 3. Package format (`.securetrack`)

A `.securetrack` file is a standard ZIP archive (`ZIP_STORED`,
no compression) with two members:

* `metadata.json` — UTF-8 JSON, also used as AES-GCM associated data.
* `encrypted_audio.bin` — AES-GCM ciphertext concatenated with the
  16-byte authentication tag.

### 3.1 Metadata schema (version 1)

```json
{
  "format_version":      1,
  "algorithm":           "AES-256-GCM",
  "kdf":                 "scrypt",
  "kdf_params":          {"n": 32768, "r": 8, "p": 1, "length": 32},
  "salt":                "<base64 16 bytes>",
  "nonce":               "<base64 12 bytes>",
  "original_filename":   "sample.wav",
  "original_size_bytes": 88244,
  "sha256_original":     "<hex 64>",
  "created_utc":         "2026-05-04T12:00:00Z",
  "labels":              {"project": "demo", "collaborator": "alice"}
}
```

The metadata is serialised with `json.dumps(..., sort_keys=True,
separators=(",", ":"))` so that the bytes used as AES-GCM associated
data are deterministic.

### 3.2 Why ZIP, not a custom binary header?

* Inspectable with standard tools (`unzip -p`).
* The Python standard library already ships `zipfile`, so the format
  is dependency-free.
* Future versions can add new members (e.g. `recipients.json`,
  `signature.bin`) without breaking existing readers, as long as
  `metadata.format_version` is bumped.

### 3.3 Expected overhead

| Component                | Approx. size |
|--------------------------|--------------|
| ZIP central directory    | ~150 B       |
| `metadata.json`          | ~400–600 B   |
| AES-GCM tag              | 16 B         |

So we expect a roughly constant 600–800 byte overhead. For a 5 MB
WAV that is ~0.015 % overhead.

## 4. Module map

```
crypto.py            primitives only — no I/O, no formats
package.py           builds and parses .securetrack archives
metrics.py           pure size / throughput helpers
benchmark.py         glue: timing + tamper test + CSV row
cli.py               argparse front-end
gui.py               Tkinter front-end
audacity_bridge.py   placeholder for native Audacity integration
```

The dependency graph is strictly downward: `crypto` knows nothing
about packages; `package` knows nothing about benchmarks; `benchmark`
knows nothing about CLI/GUI. This makes each layer easy to test on
its own.

## 5. Threat model (informal)

**In scope.**
* A passive eavesdropper on the transport channel reading the
  contents of a `.securetrack` file.
* An adversary tampering with bytes of the file in transit (flipping
  bits, replacing the ciphertext, modifying the metadata).
* A storage provider holding the file at rest who tries to read it.
* A recipient trying to brute-force the passphrase offline (mitigated
  by Scrypt cost parameters; ultimately bounded by passphrase
  entropy).

**Out of scope.**
* Compromise of the sender or recipient endpoint while plaintext is
  in memory.
* Side-channel attacks on the local machine.
* Coercion or social engineering of the passphrase.
* Recipients re-sharing the decrypted WAV after they have legitimately
  unwrapped the package.

## 6. Backlog of next steps

1. **Per-recipient public-key encryption.** Replace the passphrase
   with X25519 ephemeral key agreement; store one wrapped data key
   per recipient in `recipients.json`.
2. **Native Audacity integration** via `mod-script-pipe`. See
   `audacity_integration_notes.md`.
3. **Streaming encrypt/decrypt** so files larger than free RAM are
   supported (chunked GCM with a counter-style nonce strategy).
4. **Audit log inside the package**: who created it, on what host,
   with what tool version. Useful for the dissertation evaluation.
5. **Hardened GUI**: drag-and-drop, progress reporting, project /
   collaborator picker, integrated benchmark view.
