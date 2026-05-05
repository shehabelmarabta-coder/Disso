# SecureTrack — Secure encrypted audio sharing for Audacity

A bridge-based Audacity plugin prototype that encrypts unreleased
audio tracks locally before sharing them. Submitted as the
implementation artefact for a BSc Computing and Information
Technology dissertation at the University of Surrey.

## Overview

Music collaborators routinely exchange unreleased WAV stems through
generic services such as Dropbox, Google Drive, email and messaging
apps. None of those channels were designed for managing creative
material, which leads to fragmented access control and a real risk
of leaks.

SecureTrack wraps an exported WAV file in a passphrase- (or key-)
protected ``.securetrack`` package that only the intended
collaborator can open. The application can also drive Audacity over
its ``mod-script-pipe`` scripting interface to export the active
project automatically and seal it in one step, without the user
having to use Audacity's *File ▸ Export* menu by hand.

## The problem

Unreleased music has commercial and reputational value. Sharing it
through general-purpose cloud services means:

* Links can be forwarded to people who were never authorised.
* Folders often remain accessible long after the collaboration ends.
* The audio sits in plaintext on a third-party server.
* Leaks are usually traced not to weaknesses in the audio software
  but to weaknesses in the file-sharing workflow.

SecureTrack offers an alternative: encrypt the audio locally before
it ever leaves the sender's machine, and let the user transport the
sealed package through whatever channel they already trust.

## Key features

* **Local encryption.** Audio is encrypted on the sender's machine
  using AES-256-GCM with a passphrase-derived key (Scrypt KDF).
* **Tamper detection.** Any modification to the package — the audio,
  the metadata, even a single bit — causes decryption to fail with a
  clear error.
* **Hash verification.** Every decryption verifies a SHA-256 of the
  recovered audio against a value stored in the package.
* **Audacity integration.** The application can talk to a running
  Audacity instance through ``mod-script-pipe``, automatically select
  every track, export the project to a temporary WAV and encrypt it,
  deleting the temporary plaintext on the way out.
* **Three-tab desktop GUI.** Encrypt WAV / Decrypt Package / Audacity
  Export. Aimed at musicians, not security engineers.
* **Command line and benchmark tools.** A scripted ``benchmark``
  subcommand records timing, throughput, size overhead, hash match
  and tamper detection to a CSV file for the dissertation
  evaluation.
* **Optional public-key recipients and signing.** Advanced users can
  encrypt to an X25519 public key instead of (or in addition to) a
  passphrase, and sign packages with an Ed25519 key. These options
  live in the *Advanced* sections of the GUI and as command-line
  flags; the default workflow is passphrase-only.

## How the prototype works

```
  Audacity project
        │
        │  mod-script-pipe                          File ▸ Export
        │  (auto SelectAll + Export2)               (manual fallback)
        ▼
   tmp/render.wav (deleted after use)         exported.wav
        │                                              │
        ▼                                              ▼
                  ┌─────────────────────────┐
                  │   SecureTrack encrypt    │
                  │   AES-256-GCM + Scrypt   │
                  └────────────┬────────────┘
                               ▼
                       share.securetrack
                               │
                               │  email / Dropbox / WeTransfer / …
                               ▼
                  ┌─────────────────────────┐
                  │   SecureTrack decrypt    │
                  │   verify hash + tamper   │
                  └────────────┬────────────┘
                               ▼
                       recovered.wav  →  Audacity
```

This is a **bridge-based Audacity plugin prototype**: the application
talks to Audacity through its scripting interface rather than being
compiled into Audacity as a native C++ plug-in. The dissertation
documents this honestly throughout.

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

The window opens with three tabs: **Encrypt WAV**, **Decrypt
Package**, and **Audacity Export**.

### Encrypting a WAV file

1. Open the **Encrypt WAV** tab.
2. Choose the WAV file to protect.
3. Choose where to save the ``.securetrack`` package (the app
   suggests a sensible default).
4. Enter a passphrase. Choose at least 12 characters and share it
   with the recipient through a different channel.
5. Click **Encrypt**.

### Decrypting a secure package

1. Open the **Decrypt Package** tab.
2. Choose the ``.securetrack`` file you received.
3. Choose where to save the recovered WAV.
4. Enter the passphrase. (Advanced users with an X25519 private key
   can pick the key file in the *Advanced (optional)* section.)
5. Click **Decrypt**.

If the passphrase is wrong, or the package has been tampered with in
transit, the app reports the failure and writes no audio.

### Enabling Audacity ``mod-script-pipe``

The Audacity Export tab needs Audacity's scripting interface, which
ships with Audacity but is **not** enabled by default:

1. In Audacity, open *Edit ▸ Preferences ▸ Modules*.
2. Set **mod-script-pipe** to **Enabled**.
3. Restart Audacity.
4. Open an audio project (with audio in it).

### Using the Audacity Export tab

1. Open the **Audacity Export** tab.
2. Click **Test Audacity Connection**. The status line should change
   to *Connected to Audacity.* If it does not, follow the on-tab
   guidance.
3. Choose where to save the ``.securetrack`` package.
4. Enter a passphrase (or pick a recipient public key in *Advanced
   (optional)*).
5. Click **Export from Audacity and Encrypt**.

The application asks Audacity to select every track, exports the
project to a temporary WAV, encrypts that WAV into the package and
overwrites the temporary file with zeros before deleting it.

## Running benchmarks

The dissertation evaluation chapter (Chapter 5) is driven from the
``benchmark`` subcommand:

```bash
python -m securetrack.cli benchmark ^
    -i examples\sample.wav ^
    -o results\benchmark_results.csv ^
    -p "test password"
```

Each call appends one row to the CSV with original size, encrypted
size, size overhead in bytes and percent, encryption / decryption
times, throughput, SHA-256 hashes, hash match and tamper detection.

## Running the tests

```bash
python -m pytest -v
```

The test suite covers correctness of the round-trip, rejection of
wrong passphrases and wrong private keys, tamper detection across
the ciphertext / metadata / recipients list, signature verification,
the CLI subcommands and the Audacity bridge against a fake pipe.

## Demonstration commands (Windows)

These are the exact commands used to produce the dissertation
screenshots. Run them from the project root after activating the
virtual environment.

```bat
REM 1. Install
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"

REM 2. Generate a sample WAV (no real music ships with the repo)
python examples\generate_sample_wavs.py

REM 3. Launch the desktop app
python -m securetrack.gui
REM   - or the launcher:
run_securetrack.bat

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

REM 6. Run a benchmark and append a row to results\benchmark_results.csv
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

## Current limitations

* This is a **dissertation prototype**, not a production-ready
  security product. It has not been independently audited.
* It is a **bridge-based Audacity plugin prototype** that uses
  Audacity's ``mod-script-pipe`` interface, **not** a native C++
  Audacity plug-in installed inside Audacity.
* No cloud upload or relay — packages are produced locally and the
  user transports them with whichever service they already trust.
* The recipient is responsible for protecting the passphrase or
  private key. Once they decrypt a package the audio is an ordinary
  WAV, and the sender cannot technically prevent further
  redistribution.
* Secure deletion of the temporary WAV produced by the Audacity
  bridge is best-effort; on SSDs and modern copy-on-write
  filesystems an overwrite cannot guarantee that no copy remains.

## Future improvements

* A native Audacity menu plug-in so the application appears as
  *File ▸ Encrypt and share…* inside Audacity itself.
* Optional cloud relay with revocable share links.
* Better identity management (a keyring of trusted collaborators
  rather than ad-hoc passphrases).
* Revocation: a way for the sender to invalidate a package after the
  fact, even if the recipient still has it.
* A packaged Windows installer.
