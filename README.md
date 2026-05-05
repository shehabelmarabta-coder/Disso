# SecureTrack — Encrypted Track Sharing Prototype for Audacity

> **BSc Computing and Information Technology dissertation, University of Surrey.**
> Project title: *Secure End-to-End Encrypted Track Sharing Plugin for Audacity.*

## Project summary

Music collaborators routinely exchange unreleased WAV stems through
Dropbox, Google Drive, email and messaging apps. These channels were
never designed for managing creative material, which leads to
fragmented access control and a tangible risk of leaks. SecureTrack
is a Python prototype that takes a WAV file exported from Audacity,
encrypts it locally and produces a portable ``.securetrack`` package
that only the intended collaborator(s) can open.

This repository contains the dissertation implementation artefact.
The current release is **format v2**: the package is bound to one or
more recipients (passphrase or X25519 public key), is optionally
signed by the sender with an Ed25519 key, and is encrypted in
fixed-size AEAD chunks so very large WAVs do not have to fit in
memory.

## Why the prototype exists

* To demonstrate that encrypted, integrity-checked exchange of audio
  stems can be implemented as an additional step in a normal Audacity
  export workflow.
* To produce reproducible measurements (size overhead, throughput,
  tamper detection) for the dissertation evaluation chapter.
* To provide a clean foundation that later versions can build on
  (cloud relay, project-level key management, native Audacity plugin
  GUI, revocation and audit logging).

## What's new in v2

* **Per-recipient public-key encryption.** A package can be addressed
  to one or more X25519 public keys; the recipient unwraps with
  their private key, no shared secret needed.
* **Mixed recipients.** A single package can target several pubkey
  recipients *and* a passphrase fallback at the same time.
* **Optional Ed25519 signature.** The sender can sign metadata,
  recipient list and ciphertext digest. Recipients verify with the
  embedded public key, or with a public key supplied out of band.
* **Chunked AEAD streaming.** The audio is encrypted in 1 MiB chunks
  by default; each chunk authenticates ``metadata || chunk_index ||
  num_chunks`` so chunks cannot be reordered, dropped or replayed.
* **Real Audacity bridge.** ``audacity_bridge.py`` now drives
  ``mod-script-pipe`` for ``Export2`` and ``Help`` commands, with a
  high-level ``secure_export_from_audacity`` helper that exports,
  encrypts and securely deletes the temporary WAV.
* **Hardened GUI.** Two-tab Tkinter window with a recipient list
  picker, signing-key fields and a background progress bar.

## Repository layout

```
secure-audacity-track-sharing/
├── README.md
├── pyproject.toml
├── .gitignore
├── .gitlab-ci.yml
├── src/securetrack/
│   ├── __init__.py
│   ├── crypto.py            # AEAD + Scrypt + chunked streaming + Ed25519
│   ├── keys.py              # X25519 / Ed25519 keypair gen + PEM I/O
│   ├── recipients.py        # per-recipient content-key wrapping
│   ├── package.py           # .securetrack v2 package format
│   ├── metrics.py           # pure metric helpers
│   ├── benchmark.py         # encrypt+decrypt timing + tamper test
│   ├── cli.py               # argparse subcommands
│   ├── gui.py               # Tkinter GUI (progress bar, recipient list)
│   └── audacity_bridge.py   # mod-script-pipe driver + secure_export
├── tests/                   # 60+ pytest tests
├── examples/
│   └── generate_sample_wavs.py
├── docs/
│   ├── evaluation_plan.md
│   ├── user_manual.md
│   ├── technical_design.md
│   └── audacity_integration_notes.md
└── results/                 # benchmark CSVs (gitignored)
```

## Install

The prototype targets **Python 3.11+** and depends only on the
[`cryptography`](https://cryptography.io) library.

```bash
git clone <this repository>
cd secure-audacity-track-sharing
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Quick demo (passphrase only)

```bash
python examples/generate_sample_wavs.py

python -m securetrack.cli encrypt \
    -i examples/sample.wav -o results/sample.securetrack -p "test password"

python -m securetrack.cli decrypt \
    -i results/sample.securetrack -o results/recovered.wav -p "test password"

sha256sum examples/sample.wav results/recovered.wav     # hashes match
```

## Per-recipient public-key sharing

Generate a long-term X25519 keypair for the recipient (Bob):

```bash
python -m securetrack.cli keygen --kind x25519 \
    --private-out keys/bob.priv.pem --public-out keys/bob.pub.pem
```

Alice (the sender) encrypts to Bob's public key, with no shared
passphrase:

```bash
python -m securetrack.cli encrypt \
    -i examples/sample.wav -o results/for-bob.securetrack \
    --recipient keys/bob.pub.pem
```

Bob decrypts with his private key:

```bash
python -m securetrack.cli decrypt \
    -i results/for-bob.securetrack -o results/recovered.wav \
    --key keys/bob.priv.pem
```

Multiple recipients are supported by repeating ``--recipient``, and a
passphrase fallback can be added with ``-p``.

## Signing a package (Ed25519)

```bash
python -m securetrack.cli keygen --kind ed25519 \
    --private-out keys/alice.sign.pem --public-out keys/alice.verify.pem

python -m securetrack.cli encrypt \
    -i examples/sample.wav -o results/signed.securetrack \
    --recipient keys/bob.pub.pem \
    --signing-key keys/alice.sign.pem \
    --label project=demo --creator-name alice

python -m securetrack.cli decrypt \
    -i results/signed.securetrack -o results/recovered.wav \
    --key keys/bob.priv.pem \
    --expect-signed-by keys/alice.verify.pem
```

If the signature does not verify under ``keys/alice.verify.pem``, the
decrypt subcommand exits with status 5 and writes no plaintext.

## Inspecting a package without decrypting

```bash
python -m securetrack.cli inspect -i results/signed.securetrack --json
```

Prints the canonical metadata JSON. The recipient list and ciphertext
remain encrypted; only the metadata header is human-readable.

## Benchmarks

```bash
python -m securetrack.cli benchmark \
    -i examples/sample.wav -o results/benchmark_results.csv -p "test password"
```

Appends one row to the CSV with timing, throughput, size overhead and
tamper-detection columns. See ``docs/evaluation_plan.md``.

## GUI

```bash
python -m securetrack.gui
```

Two tabs (Encrypt / Decrypt), recipient list with Add/Remove, signing
key fields, a background progress bar and a status line. The GUI uses
threads so the main loop stays responsive while Scrypt runs.

## Audacity integration

* **Manual workflow (works today):** export a WAV from Audacity
  (*File ▸ Export ▸ Export as WAV*) and run SecureTrack on the file.
* **Native bridge (works today, requires Audacity with mod-script-pipe
  enabled):** call
  ``securetrack.audacity_bridge.secure_export_from_audacity``. It
  drives ``Export2`` over the script pipe, encrypts the resulting WAV,
  then securely deletes the temporary plaintext.

See ``docs/audacity_integration_notes.md`` for the protocol details
and known caveats (temporary plaintext on disk, pipe authentication
on shared machines).

## Running the tests

```bash
python -m pytest -v
```

Covers crypto round-trip, X25519 / Ed25519 PEM I/O, multi-recipient
unwrap, chunked streaming, signature verification, tamper detection,
the CLI subcommands and the Audacity pipe driver against a fake FIFO
server.

## Current limitations (honest list)

* This is still a **prototype**. It has not been independently audited.
* No cloud relay — packages are produced locally; the user transports
  them via their preferred channel.
* Once a recipient has decrypted a package, **access cannot be
  revoked** (same as any plain file share).
* The Audacity bridge writes a temporary plaintext WAV to disk.
  ``_secure_delete`` is best-effort on journalled / SSD filesystems.
* The Tkinter GUI is functional but minimal; drag-and-drop and per-
  project key management remain on the backlog.

## Next development steps

1. Cloud relay with at-rest re-encryption and revocable links.
2. Project-level key management (one X25519 keypair per project,
   per-collaborator membership).
3. Header-only download + streaming decrypt, so a recipient can begin
   playback before the whole package has been fetched.
4. Native Audacity menu item via Nyquist that calls the Python bridge
   in a daemon process, removing the manual Export step entirely.
5. Independent security review of the v2 format (third-party
   cryptographer or `cryptography.io` mailing list feedback).
