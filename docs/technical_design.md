# Technical Design

This document supports Chapter 4 of the dissertation. It describes
SecureTrack's design objectives, architecture, encryption choices,
how the prototype integrates with Audacity, and the system's
limitations.

## 1. System overview

SecureTrack is a Python desktop application that integrates with
Audacity at the export stage. It accepts a WAV file (either
exported manually from Audacity into a watched local folder, or
rendered automatically through Audacity's scripting interface),
encrypts the audio locally and produces a single sealed file with
the ``.securetrack`` extension. A recipient with the matching
passphrase or private key can then recover the original WAV and
import it back into Audacity.

The application has three main components:

* a small cryptographic core (``securetrack.crypto``,
  ``securetrack.package``, ``securetrack.recipients``,
  ``securetrack.keys``);
* the desktop GUI (``securetrack.gui``) and command-line interface
  (``securetrack.cli``); and
* the Audacity-facing layer, which combines a watched-folder driver
  (``securetrack.watch_folder``) and the ``mod-script-pipe`` driver
  (``securetrack.audacity_bridge``).

This is a **bridge-based Audacity plugin prototype**: it does not
replace Audacity. Instead, it integrates at the export stage by
either communicating with Audacity through ``mod-script-pipe`` or
monitoring a local Audacity export folder and encrypting exported
WAV files immediately. It is **not** a native C++ Audacity plug-in
compiled inside Audacity.

## 2. Design objectives

The prototype was designed against four objectives drawn from the
problem statement:

1. **Local encryption.** The audio is encrypted on the sender's
   machine before it leaves the device. The user's existing
   sharing channel is treated as untrusted.
2. **Authenticity and integrity.** A recipient must be able to
   detect any modification of the package, no matter how small.
3. **Sit alongside the production workflow.** The application has
   to fit a normal Audacity export workflow without forcing
   collaborators to learn cryptography vocabulary.
4. **Reproducible evaluation.** The implementation has to expose
   timing, throughput and correctness measurements so the
   dissertation evaluation chapter can be repeated by anyone.

## 3. Architecture

```
                   ┌───────────────────────────────┐
                   │   securetrack.gui (Tkinter)   │
                   │   securetrack.cli (argparse)  │
                   └───────────────┬───────────────┘
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        ▼                          ▼                          ▼
┌─────────────────┐      ┌───────────────────┐      ┌───────────────────┐
│ watch_folder    │      │ audacity_bridge   │      │ benchmark         │
│ (poll Exports/) │      │ (mod-script-pipe) │      │ (timing + CSV)    │
└────────┬────────┘      └─────────┬─────────┘      └───────────────────┘
         │                         │
         └────────────┬────────────┘
                      ▼
            ┌───────────────────┐
            │ package           │
            │ (.securetrack     │
            │  archive format)  │
            └────────┬──────────┘
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
 ┌────────────┐ ┌────────────┐ ┌────────────┐
 │ recipients │ │ keys       │ │ crypto     │
 └────────────┘ └────────────┘ └────────────┘
```

The dependency graph is strictly downward. ``crypto`` knows nothing
about packages; ``package`` knows nothing about user interfaces;
``audacity_bridge``, ``watch_folder`` and ``benchmark`` use
``package`` but are independent of each other. Each module can be
tested on its own.

## 4. Workflow diagram

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

The encryption step happens **before** the package leaves the
sender's machine; the sharing channel only ever sees ciphertext.

## 5. Manual WAV workflow

```
   Audacity project ── File ▸ Export ──► exported.wav
                                              │
                                              ▼
                              securetrack encrypt / GUI
                                              │
                                              ▼
                                     share.securetrack
```

This path uses Audacity's built-in *Export* command and the
SecureTrack *Encrypt WAV* tab. It works with any version of
Audacity and makes no assumptions about scripting modules.

## 6. Audacity bridge workflow (mod-script-pipe)

```
   Audacity project ── mod-script-pipe ──► SelectAll
                                            Export2 → temp/render.wav
                                              │
                                              ▼
                                    securetrack encrypt
                                              │
                                              ▼
                                     share.securetrack
                                              │
                                              ▼
                          temp/render.wav (overwritten + unlinked)
```

The bridge issues two commands over Audacity's named pipe:

* ``SelectAll:`` so that *Export2* picks up every track. Without
  it, Audacity exports only the current selection — often empty
  when the user has just opened a project — which manifests as a
  near-empty WAV. The bridge surfaces that with a clear error
  ("Audacity exported an empty or near-empty WAV. Make sure the
  project contains audio.").
* ``Export2: Filename="<path>" NumChannels=2`` to render the
  project to a temporary WAV.

On Windows the named pipes live in the NT object namespace
(``\\.\pipe\ToSrvPipe`` / ``\\.\pipe\FromSrvPipe``), which means
``Path.exists`` always reports them missing and Python's text-mode
``open`` cannot drive them. The bridge therefore uses ``pywin32``
(``win32pipe.WaitNamedPipe`` / ``win32file.CreateFile`` /
``WriteFile`` / ``PeekNamedPipe`` / ``ReadFile``) on Windows and
plain FIFO ``open()`` on POSIX. The Windows protocol terminator is
``\r\n\0`` rather than ``\n``; the bridge picks the right
end-of-line automatically.

## 7. Watched-folder workflow

```
   Audacity project ── File ▸ Export ──► Documents/SecureTrack/Exports/
                                                   │
                                                   ▼  watcher detects new WAV
                                          SecureTrack encrypt
                                                   │
                                                   ▼
                                  Documents/SecureTrack/Secure Packages/
                                                   │
                                                   ▼  (optional)
                                  Documents/SecureTrack/Archive/  (move)
                                  ─ or ─  the WAV is overwritten + unlinked
                                  ─ or ─  the WAV is left where it is (default)
```

The watcher (``securetrack.watch_folder.Watcher``) is a small
background thread that polls the Exports folder every ~1.5 s. A
file is only encrypted once its size has stayed unchanged for at
least 2 s, so partially-written WAVs are never read mid-export.
Each ``(path, size, mtime)`` triple is processed at most once,
which means re-exporting the same filename with new content
re-encrypts it but a stable file is never re-encrypted.

Three file-handling modes are supported and chosen in the GUI:

| Mode    | Effect after a successful encryption                                     |
|---------|--------------------------------------------------------------------------|
| keep    | The exported WAV is left in place (default; safest).                      |
| move    | The exported WAV is moved into ``Documents/SecureTrack/Archive``.         |
| delete  | The exported WAV is overwritten with zeros and unlinked (best-effort).    |

## 8. How SecureTrack fits into the Audacity workflow

* **Audacity remains the creative production tool.** SecureTrack
  does not replace Audacity, edit audio, or alter the project file.
* **SecureTrack integrates at the export stage.** Either the user
  exports manually into a watched local folder, or SecureTrack
  asks Audacity to render the active project through its scripting
  interface.
* **Encryption happens before the file is uploaded or sent.** The
  sharing channel only ever sees ciphertext, which reduces reliance
  on the access control of cloud services.
* **The recipient decrypts locally** and imports the recovered WAV
  back into Audacity exactly as they would import any other WAV.

## 9. Encryption design

### 9.1 Why local encryption

The threat model assumes the *channel* (cloud storage, email
provider, messenger) is untrusted. By encrypting on the sender's
machine before the audio is uploaded, the cloud provider holds
only ciphertext. This matches the way TLS, age, GPG-encrypted
backups and similar tools approach the same problem.

### 9.2 Why AES-GCM

AES-256 in Galois/Counter Mode (GCM) was chosen because:

* GCM provides confidentiality **and** authenticity in a single
  primitive — any modification to the ciphertext or the
  authenticated metadata invalidates the 16-byte tag and decryption
  fails. This is exactly the property the dissertation evaluates as
  "tamper detection".
* It is a standard, widely audited mode available in
  ``cryptography.hazmat.primitives.ciphers.aead.AESGCM``.
* It is hardware-accelerated on every machine the prototype will
  run on.

### 9.3 Why Scrypt for passphrase keys

Scrypt is a memory-hard key-derivation function recommended by
OWASP for password-derived keys. The cost parameters
(``N = 2¹⁵, r = 8, p = 1, length = 32``) give roughly a few hundred
milliseconds and ~30 MB of memory on a modern laptop, which is fast
enough for an interactive workflow but expensive enough to make
offline brute force prohibitive for a passphrase of reasonable
length.

### 9.4 Why X25519 + HKDF for public-key recipients

Optional public-key recipients use X25519 elliptic-curve
Diffie–Hellman with HKDF-SHA256 to derive a wrapping key, then
AES-GCM to wrap the per-package content key. The HKDF ``info``
string binds the wrapping key to the protocol and to the specific
ephemeral and recipient public keys, so the same shared secret
cannot be reused outside this construction.

## 10. Package format

A ``.securetrack`` package is a standard ZIP archive with three
required members and one optional member:

| Member                  | Required | Purpose                                                   |
|-------------------------|----------|-----------------------------------------------------------|
| ``metadata.json``       | yes      | Algorithm names, KDF parameters, chunk size, nonce prefix, original filename and size, SHA-256 of the original audio, creation timestamp. Authenticated as AES-GCM associated data. |
| ``recipients.json``     | yes      | One entry per recipient (passphrase or X25519 public key); each entry holds an AES-GCM-wrapped copy of the per-package content key. |
| ``encrypted_audio.bin`` | yes      | Concatenated AES-256-GCM chunks. Each chunk authenticates the metadata, its index and the chunk count. |
| ``signature.bin``       | optional | Ed25519 signature over the metadata, the SHA-256 of ``recipients.json`` and the SHA-256 of the ciphertext. Present only when the sender supplied a signing key. |

ZIP was chosen over a bespoke binary format because it is
inspectable with standard tools, robust, and adds only a few
hundred bytes of overhead. Inspecting the metadata of a package
without decrypting it (``securetrack inspect --json``) is
intentional — it lets a recipient see what the package claims to
contain before typing a passphrase.

## 11. Key management

Key material is stored as PEM files using ``cryptography``'s
serialisation helpers. Private key files can optionally be
encrypted at rest with a passphrase (PKCS#8 with the best
available encryption). On POSIX the private file is written with
mode ``0o600``.

Keys are generated through the ``securetrack keygen`` subcommand:

```
python -m securetrack.cli keygen --kind x25519 --private-out priv.pem --public-out pub.pem
python -m securetrack.cli keygen --kind ed25519 --private-out sign.pem --public-out verify.pem
```

The dissertation does not propose a centralised directory of
collaborator keys — that is listed under *Future improvements*.

## 12. Integrity verification

Two layers of integrity checking are applied during decryption:

1. **AES-GCM authentication** — every ciphertext chunk and every
   wrapped recipient key is authenticated with a 16-byte tag bound
   to the canonical metadata as associated data. A single-bit
   change anywhere causes decryption to fail.
2. **SHA-256 hash check** — once the audio has been decrypted, its
   SHA-256 is recomputed and compared against the value in the
   metadata. The benchmark CSV records both hashes
   (``sha256_original`` and ``sha256_decrypted``) and a boolean
   ``hash_match`` column for every run.

The optional Ed25519 signature adds a third layer when present.

## 13. Temporary file handling

The Audacity bridge writes a temporary WAV to a per-call
``tempfile.TemporaryDirectory`` and overwrites that file with
zeros (followed by ``os.fsync`` and ``unlink``) before returning.

The watch-folder mode does *not* write a temporary file — Audacity
writes the WAV directly into the user's Exports folder and
SecureTrack reads it from there. The user chooses what happens to
that exported WAV after encryption (keep, move to Archive, or
overwrite-and-unlink).

Both deletion paths are best-effort: on journalled, copy-on-write
or wear-levelled filesystems an in-place overwrite cannot guarantee
that no copy of the plaintext remains on the underlying storage.

## 14. Limitations

* This is a dissertation prototype, not a production-ready security
  product, and has not been independently audited.
* It is a bridge-based Audacity plugin prototype; it is not a
  native C++ Audacity plug-in compiled inside Audacity.
* Recipients must protect their passphrases and private keys; once
  they decrypt a package, the audio is an ordinary WAV and the
  sender cannot technically prevent further redistribution.
* Secure deletion of temporary or exported files is best-effort,
  especially on SSDs and copy-on-write filesystems.
* The watcher uses a polling loop, not OS-level filesystem events,
  to keep the dependency surface minimal.
* No cloud relay or revocable share links are implemented.

## 15. Dissertation implementation summary

The final prototype consists of a Python desktop application called
**SecureTrack** and an Audacity-facing layer that integrates with
Audacity in two ways: through Audacity's ``mod-script-pipe``
scripting interface, and by watching a local Audacity export
folder. The application allows users to encrypt exported WAV files,
decrypt secure packages, and integrate encrypted sharing into a
normal Audacity workflow without leaving the desktop. Audio is
encrypted locally before sharing using AES-256-GCM, with
Scrypt-based passphrase key derivation and SHA-256 integrity
verification. The system produces a ``.securetrack`` package that
can be distributed through normal channels while keeping the audio
content unreadable without the correct passphrase or private key.
Tamper detection and hash matching are recorded for every benchmark
run so the evaluation chapter can demonstrate correctness and
integrity directly from data.
