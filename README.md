# SecureTrack — Encrypted Track Sharing Prototype for Audacity

> **BSc Computing and Information Technology dissertation, University of Surrey.**
> Project title: *Secure End-to-End Encrypted Track Sharing Plugin for Audacity.*

## Project summary

Music collaborators routinely exchange unreleased WAV stems through
Dropbox, Google Drive, email and messaging apps. These channels were
never designed for managing creative material, which leads to
fragmented access control and a tangible risk of leaks. SecureTrack is
a Python prototype that takes a WAV file exported from Audacity,
encrypts it locally with a passphrase, and produces a portable
``.securetrack`` package that only the intended collaborator can open.

This repository contains the **first rough skeleton** described in the
dissertation implementation chapter. It is deliberately small and
honest: there is no cloud upload, no production-grade key management,
and no native Audacity plugin yet.

## Why the prototype exists

* To demonstrate that encrypted, integrity-checked exchange of audio
  stems can be implemented as an additional step in a normal Audacity
  export workflow.
* To produce reproducible measurements (size overhead, throughput,
  tamper detection) for the dissertation evaluation chapter.
* To provide a clean foundation that later versions can build on
  (per-recipient public-key access, native Audacity integration,
  cloud relay, revocation and audit logging).

## Repository layout

```
secure-audacity-track-sharing/
├── README.md
├── pyproject.toml
├── .gitignore
├── .gitlab-ci.yml
├── src/securetrack/
│   ├── __init__.py
│   ├── crypto.py            # AES-256-GCM + Scrypt key derivation
│   ├── package.py           # .securetrack package format (zip + metadata)
│   ├── metrics.py           # Pure metric helpers
│   ├── benchmark.py         # End-to-end timing + tamper test
│   ├── cli.py               # `python -m securetrack.cli ...`
│   ├── gui.py               # Minimal Tkinter GUI skeleton
│   └── audacity_bridge.py   # Placeholder for future Audacity integration
├── tests/
│   ├── test_crypto_roundtrip.py
│   ├── test_tamper_detection.py
│   └── test_metrics.py
├── examples/
│   └── generate_sample_wavs.py
├── docs/
│   ├── evaluation_plan.md
│   ├── user_manual.md
│   ├── technical_design.md
│   └── audacity_integration_notes.md
└── results/                 # Benchmark CSVs land here (gitignored)
```

## Install

The prototype targets **Python 3.11+** and depends only on the
[`cryptography`](https://cryptography.io) library. Optional extras add
`pandas` and `matplotlib` for offline analysis of the benchmark CSV.

```bash
git clone <this repository>
cd secure-audacity-track-sharing

# Recommended: a fresh virtual environment
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# Editable install with development extras (pytest, ruff)
pip install -e ".[dev]"
```

## Generating example WAVs

The repository deliberately does **not** ship any real audio. Generate
a few small synthetic WAVs first:

```bash
python examples/generate_sample_wavs.py
```

This writes ``examples/sample.wav`` (mono 440 Hz),
``examples/sample_stereo.wav`` (stereo 440 Hz / 660 Hz) and
``examples/sample_silence.wav``. They are excluded from git.

## Running encryption

```bash
python -m securetrack.cli encrypt \
    --input  examples/sample.wav \
    --output results/sample.securetrack \
    --passphrase "test password"
```

If you omit ``--passphrase`` the CLI prompts for it without echoing.

## Running decryption

```bash
python -m securetrack.cli decrypt \
    --input  results/sample.securetrack \
    --output results/recovered.wav \
    --passphrase "test password"
```

A wrong passphrase or any modification to the package causes
decryption to fail with a clear error and a non-zero exit code.

## Running benchmarks

```bash
python -m securetrack.cli benchmark \
    --input  examples/sample.wav \
    --output results/benchmark_results.csv \
    --passphrase "test password"
```

The benchmark performs one encrypt and one decrypt round-trip,
verifies SHA-256 equality, runs a one-byte tamper test, and appends a
single row to the CSV. The header is written automatically the first
time the file is created.

## Running the GUI skeleton

```bash
python -m securetrack.gui
```

This is a minimal Tk window with **Encrypt WAV…** and **Decrypt
package…** buttons. It reuses the same library code as the CLI.

## Running the tests

```bash
pytest -v
```

The test suite covers correctness of the round-trip, rejection of
wrong passphrases, tamper detection across the ciphertext / metadata /
ZIP container, and the pure-Python metric helpers.

## How this links to Audacity

The prototype works on **files exported from Audacity**: the user
exports a project to WAV via ``File → Export → Export as WAV`` and
then runs SecureTrack on that file. ``src/securetrack/audacity_bridge.py``
documents the planned native integration via Audacity's
``mod-script-pipe`` interface but does not pretend to implement it
yet. See ``docs/audacity_integration_notes.md`` for the full plan.

## Current limitations (honest list)

* This first version is a **prototype**, not a production-ready
  security product.
* It does **not** provide cloud sharing — packages are produced
  locally and the user transports them by their preferred channel.
* It does **not** provide native Audacity plug-in integration yet.
* Passphrase exchange must be handled out of band by the users.
* Once a recipient has decrypted a package, **access cannot be
  revoked** — the same limitation as any plain file share.
* A future version should adopt **public-key cryptography per
  recipient** (e.g. age, NaCl box) so that no shared secret has to be
  exchanged ahead of time.

## Next development steps

See ``docs/technical_design.md`` for the prioritised backlog. The
first five items are roughly:

1. Per-recipient public-key encryption (X25519 + AES-GCM).
2. Native Audacity bridge via ``mod-script-pipe``.
3. Streaming I/O so very large WAV files do not have to fit in
   memory.
4. Audit log inside the package describing who created it and when.
5. Hardened GUI with progress bar, drag-and-drop and project-level
   key management.
