# SecureTrack — Secure encrypted audio sharing for Audacity

A bridge-based Audacity plugin prototype that integrates with
Audacity at the export stage and encrypts unreleased audio locally
before sharing. Submitted as the implementation artefact for a BSc
Computing and Information Technology dissertation at the University
of Surrey.

## Overview

Music collaborators routinely exchange unreleased WAV stems through
generic services such as Dropbox, Google Drive, email and messaging
apps. None of those channels were designed for managing creative
material, which leads to fragmented access control and a real risk
of leaks.

SecureTrack is **not** a separate generic encryption tool. It is an
Audacity workflow integration: it sits at the export stage of the
production workflow, encrypts the exported WAV locally and produces a
single ``.securetrack`` package that can travel through whatever
sharing channel the user already trusts.

The application offers two ways to integrate with Audacity:

1. **Watched export folder.** SecureTrack watches a local
   ``Documents/SecureTrack/Exports`` folder. The user exports from
   Audacity into that folder as normal; SecureTrack detects the new
   WAV and encrypts it into ``Documents/SecureTrack/Secure Packages``
   automatically.
2. **Direct bridge via mod-script-pipe.** SecureTrack drives Audacity
   over its scripting interface, asks it to *Select All* and *Export
   to* a temporary WAV, encrypts that WAV, and securely deletes the
   temporary file.

## Workflow diagram

```
            Audacity Project
                  ↓
         Export WAV locally
                  ↓
       SecureTrack encrypts locally
                  ↓
          .securetrack package
                  ↓
    Send through email / Drive / messaging
                  ↓
       Recipient decrypts locally
                  ↓
      Recovered WAV imported into Audacity
```

The audio is encrypted **before** it leaves the sender's machine. The
sharing channel only ever sees ciphertext.

## Recommended Audacity Workflow

The simplest end-to-end use of the prototype:

1. Open SecureTrack.
2. On the **Audacity Workflow** tab, click *Create / Open SecureTrack
   Folders*.
3. Type a passphrase and click *Start Watching Export Folder*.
4. Open Audacity and work on your project as normal.
5. Export the audio as WAV into ``Documents/SecureTrack/Exports``.
6. SecureTrack detects the exported WAV and writes a ``.securetrack``
   package in ``Documents/SecureTrack/Secure Packages`` automatically.
7. Send the ``.securetrack`` package to your collaborator through any
   channel.
8. The collaborator opens SecureTrack, goes to the *Decrypt Package*
   tab, picks the package and the same passphrase, and saves the
   recovered WAV.
9. The collaborator imports the recovered WAV into Audacity and the
   work continues.

This is the cleanest path because the export stays local and the
audio is encrypted before it ever touches a cloud service.

## Key features

* **Local encryption.** Audio is encrypted on the sender's machine
  using AES-256-GCM with a passphrase-derived key (Scrypt KDF).
* **Watched export folder.** A simple poll-based watcher encrypts
  new WAV files automatically; the user keeps using Audacity's
  built-in *File ▸ Export* command without any extra steps.
* **Direct Audacity bridge.** When ``mod-script-pipe`` is enabled the
  application can render the active Audacity project directly,
  selecting all tracks first and refusing empty exports with a clear
  error.
* **Tamper detection.** Any modification to the package — the audio,
  the metadata, even a single bit — causes decryption to fail with a
  clear error.
* **Hash verification.** Every decryption verifies a SHA-256 of the
  recovered audio against a value stored in the package.
* **Three-tab desktop GUI.** Audacity Workflow / Encrypt WAV /
  Decrypt Package, aimed at musicians rather than security
  engineers.
* **Optional public-key recipients and signing.** Available in the
  *Advanced* sections of the GUI and as command-line flags.
* **Local benchmarks.** A scripted ``benchmark`` subcommand records
  timing, throughput, size overhead, hash match and tamper detection
  to a CSV for the dissertation evaluation.

## Repository layout

```
securetrack/
├── README.md
├── pyproject.toml
├── .gitignore
├── run_securetrack.bat
├── src/
│   └── securetrack/
│       ├── audacity_bridge.py
│       ├── benchmark.py
│       ├── cli.py
│       ├── crypto.py
│       ├── gui.py
│       ├── keys.py
│       ├── metrics.py
│       ├── package.py
│       ├── recipients.py
│       └── watch_folder.py
├── tests/
│   ├── test_audacity_bridge.py
│   ├── test_benchmark.py
│   ├── test_cli.py
│   ├── test_roundtrip.py
│   ├── test_security.py
│   └── test_watch_folder.py
├── examples/
│   ├── audacity_pipe_test.py
│   └── generate_sample_wavs.py
├── docs/
│   ├── audacity_macro_notes.md
│   ├── evaluation_plan.md
│   ├── packaging_notes.md
│   ├── technical_design.md
│   └── user_manual.md
└── results/
    └── .gitkeep
```

## Installation

The prototype targets **Python 3.11+** and depends on the
``cryptography`` library. On Windows it also installs ``pywin32``
automatically (required for the Audacity bridge over named pipes).

```bash
git clone <this repository>
cd securetrack

python -m venv .venv
.venv\Scripts\activate           REM Windows
source .venv/bin/activate         # macOS / Linux

pip install -e ".[dev]"
```

## Running the desktop app

```bash
python -m securetrack.gui
```

On Windows you can double-click ``run_securetrack.bat`` instead — it
uses the local virtual environment if one exists, otherwise the
system Python.

The window opens with three tabs:

* **Audacity Workflow** — the recommended path. Workspace folders,
  recipient passphrase, file-handling option (keep/move/delete
  exported WAV), and two action panes (watch the Exports folder, or
  drive Audacity directly).
* **Encrypt WAV** — encrypt a WAV that already lives somewhere on
  disk in one shot.
* **Decrypt Package** — recover a WAV from a ``.securetrack`` package.

### Encrypting a WAV manually

1. Open the **Encrypt WAV** tab.
2. Choose the WAV file and where to save the package.
3. Enter a passphrase (≥12 characters).
4. Click **Encrypt**.

### Decrypting a secure package

1. Open the **Decrypt Package** tab.
2. Choose the ``.securetrack`` file and where to save the recovered
   WAV.
3. Enter the passphrase. Advanced users with an X25519 private key
   can pick the key file under *Advanced (optional)*.
4. Click **Decrypt**.

A wrong passphrase or any modification to the package causes
decryption to fail with a clear error and writes no audio.

### Enabling Audacity ``mod-script-pipe``

Required only for *Option B — Export directly from Audacity* on the
Audacity Workflow tab:

1. In Audacity, *Edit ▸ Preferences ▸ Modules*.
2. Set **mod-script-pipe** to **Enabled**.
3. Restart Audacity and open an audio project.

## Demonstration commands (Windows)

```bat
REM 1. Install
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"

REM 2. Generate a sample WAV
python examples\generate_sample_wavs.py

REM 3. Launch the desktop app
run_securetrack.bat
REM   (or: python -m securetrack.gui)

REM 4. Encrypt a sample WAV from the command line
python -m securetrack.cli encrypt ^
    -i examples\sample.wav ^
    -o results\sample.securetrack ^
    -p "demo passphrase"

REM 5. Decrypt the package back to a WAV
python -m securetrack.cli decrypt ^
    -i results\sample.securetrack ^
    -o results\sample_recovered.wav ^
    -p "demo passphrase"

REM 6. Run a benchmark
python -m securetrack.cli benchmark ^
    -i examples\sample.wav ^
    -o results\benchmark_results.csv ^
    -p "demo passphrase"

REM 7. Test the Audacity connection
python -m securetrack.cli audacity-test

REM 8. Export from Audacity and encrypt in one step
python -m securetrack.cli audacity-export ^
    -p "demo passphrase" ^
    --output results\audacity_export.securetrack

REM 9. Decrypt the Audacity-exported package
python -m securetrack.cli decrypt ^
    -i results\audacity_export.securetrack ^
    -o results\audacity_recovered.wav ^
    -p "demo passphrase"
```

## Running the tests

```bash
python -m pytest -v
```

The test suite covers the cryptographic round-trip, rejection of
wrong passphrases and wrong private keys, tamper detection across
the ciphertext / metadata / recipients list, signature verification,
the CLI subcommands, the Audacity bridge against a fake pipe, and
the watch-folder end-to-end loop.

## Current limitations

* This is a **dissertation prototype**, not a production-ready
  security product. It has not been independently audited.
* It is a **bridge-based Audacity plugin prototype** that integrates
  through ``mod-script-pipe`` or a watched local export folder. It is
  **not** a native C++ Audacity plug-in compiled inside Audacity.
* No cloud upload or relay — packages are produced locally and the
  user transports them via whichever service they already trust.
* The recipient is responsible for protecting the passphrase or
  private key. Once they decrypt a package the audio is an ordinary
  WAV again; the sender cannot technically prevent further
  redistribution.
* Secure deletion of the exported WAV is best-effort. On SSDs and
  copy-on-write filesystems an in-place overwrite cannot guarantee
  no remnants.
* The watcher uses a polling loop (≈1.5 s by default), not OS-level
  filesystem events. This is intentional: it has no extra
  dependencies and is reliable across platforms.

## Future improvements

* A native Audacity menu plug-in so the application appears as
  *File ▸ Encrypt and share…* inside Audacity itself.
* Optional cloud relay with revocable share links.
* Better identity management (a small keyring of trusted
  collaborators rather than ad-hoc passphrases).
* Revocation: a way for the sender to invalidate a package after the
  fact, even if the recipient still has it.
* A packaged Windows installer.
