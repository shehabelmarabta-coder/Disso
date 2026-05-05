# Technical Design

This document supports Chapter 4 of the dissertation. It describes
SecureTrack's design objectives, architecture, encryption choices and
limitations.

## 1. System overview

SecureTrack is a Python desktop application for sharing unreleased
audio between music collaborators without exposing the audio in
plaintext on third-party services. It accepts a WAV file (either
exported manually from Audacity or rendered automatically through
Audacity's scripting interface), encrypts the audio locally and
produces a single sealed file with the ``.securetrack`` extension.
A recipient with the matching passphrase or private key can then
recover the original WAV.

The application has three components:

* a small cryptographic core (``securetrack.crypto``,
  ``securetrack.package``, ``securetrack.recipients``,
  ``securetrack.keys``);
* a desktop GUI (``securetrack.gui``) and a command-line interface
  (``securetrack.cli``); and
* an Audacity bridge (``securetrack.audacity_bridge``) that drives
  Audacity over its ``mod-script-pipe`` scripting interface.

This is a **bridge-based Audacity plugin prototype**: it integrates
with Audacity through the public scripting interface rather than
being compiled into Audacity as a native C++ plug-in.

## 2. Design objectives

The prototype was designed against four objectives drawn from the
problem statement:

1. **Local encryption.** The audio must be encrypted on the sender's
   machine before it ever leaves the device. The user's existing
   sharing channel (email, Dropbox, WeTransfer) is treated as
   untrusted.
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
            ┌──────────────────────┼──────────────────────┐
            ▼                      ▼                      ▼
  ┌───────────────────┐  ┌───────────────────┐  ┌───────────────────┐
  │ audacity_bridge   │  │ package           │  │ benchmark         │
  │ (mod-script-pipe) │  │ (.securetrack     │  │ (timing + CSV)    │
  │                   │  │  archive format)  │  │                   │
  └───────────────────┘  └────────┬──────────┘  └───────────────────┘
                                  │
            ┌─────────────────────┼─────────────────────┐
            ▼                     ▼                     ▼
   ┌───────────────┐    ┌───────────────┐    ┌───────────────┐
   │ recipients    │    │ keys          │    │ crypto        │
   │ (per-recipient│    │ (X25519,      │    │ (AES-GCM,     │
   │  wrap)        │    │  Ed25519 PEM) │    │  Scrypt, HKDF)│
   └───────────────┘    └───────────────┘    └───────────────┘
```

The dependency graph is strictly downward. ``crypto`` knows nothing
about packages; ``package`` knows nothing about user interfaces;
``audacity_bridge`` and ``benchmark`` use ``package`` but are
independent of each other. Each module can be tested on its own.

## 4. Manual WAV workflow

```
   Audacity project  ──File ▸ Export──►  exported.wav
                                            │
                                            ▼
                            securetrack encrypt / GUI
                                            │
                                            ▼
                                   share.securetrack
```

This is the simplest path and works with any version of Audacity. It
makes no assumptions about scripting modules and lets the user pick
their own export format options.

## 5. Audacity bridge workflow

```
   Audacity project ──mod-script-pipe──►  SelectAll
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

* ``SelectAll:`` so that *Export2* picks up every track. Without it,
  Audacity exports only the current selection — often empty when
  the user has just opened a project — which manifests as a
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
``\r\n\0`` rather than ``\n``; the bridge picks the right end-of-line
automatically.

## 6. Encryption design

### 6.1 Why local encryption

The threat model assumes the *channel* (cloud storage, email
provider, messenger) is untrusted. By encrypting on the sender's
machine before the audio is ever uploaded, the cloud provider
holds only ciphertext. This matches the way TLS, age, GPG-encrypted
backups and similar tools approach the same problem.

### 6.2 Why AES-GCM

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

### 6.3 Why Scrypt for passphrase keys

Scrypt is a memory-hard key-derivation function recommended by
OWASP for password-derived keys. The cost parameters
(``N = 2¹⁵, r = 8, p = 1, length = 32``) give roughly a few hundred
milliseconds and ~30 MB of memory on a modern laptop, which is fast
enough for an interactive workflow but expensive enough to make
offline brute force prohibitive for a passphrase of reasonable
length.

### 6.4 Why X25519 + HKDF for public-key recipients

Optional public-key recipients use X25519 elliptic-curve
Diffie–Hellman with HKDF-SHA256 to derive a wrapping key, then
AES-GCM to wrap the per-package content key. The HKDF ``info``
string binds the wrapping key to the protocol and to the specific
ephemeral and recipient public keys, so the same shared secret
cannot be reused outside this construction.

## 7. Package format

A ``.securetrack`` package is a standard ZIP archive with three
required members and one optional member:

| Member                  | Required | Purpose                                                   |
|-------------------------|----------|-----------------------------------------------------------|
| ``metadata.json``       | yes      | Algorithm names, KDF parameters, chunk size, nonce prefix, original filename and size, SHA-256 of the original audio, creation timestamp. Authenticated as AES-GCM associated data. |
| ``recipients.json``     | yes      | One entry per recipient (passphrase or X25519 public key); each entry holds an AES-GCM-wrapped copy of the per-package content key. |
| ``encrypted_audio.bin`` | yes      | Concatenated AES-256-GCM chunks. Each chunk authenticates the metadata, its index and the chunk count, so chunks cannot be reordered, dropped or replayed. |
| ``signature.bin``       | optional | Ed25519 signature over the metadata, the SHA-256 of ``recipients.json`` and the SHA-256 of the ciphertext. Present only when the sender supplied a signing key. |

A reader can deterministically split the ciphertext into per-chunk
slices because ``chunk_size``, ``num_chunks`` and the original size
are all in the metadata. Default chunk size is 1 MiB; smaller files
fit in a single chunk.

ZIP was chosen over a bespoke binary format because it is
inspectable with standard tools, robust, and adds only a few
hundred bytes of overhead. Inspecting the metadata of a package
without decrypting it (``securetrack inspect --json``) is
intentional — it lets a recipient see what the package claims to
contain before typing a passphrase.

## 8. Key management

Key material is stored as PEM files using ``cryptography``'s
serialisation helpers. Private key files can optionally be
encrypted at rest with a passphrase (PKCS#8 with the best available
encryption). On POSIX the private file is written with mode ``0o600``
to discourage casual exposure.

Keys are generated through the ``securetrack keygen`` subcommand:

```
python -m securetrack.cli keygen --kind x25519 --private-out priv.pem --public-out pub.pem
python -m securetrack.cli keygen --kind ed25519 --private-out sign.pem --public-out verify.pem
```

The dissertation does not propose a centralised directory of
collaborator keys — that is listed under *Future improvements*.

## 9. Integrity verification

Two layers of integrity checking are applied during decryption:

1. **AES-GCM authentication** — every ciphertext chunk and every
   wrapped recipient key is authenticated with a 16-byte tag bound
   to the canonical metadata as associated data. A single-bit
   change anywhere causes decryption to fail.
2. **SHA-256 hash check** — once the audio has been decrypted, its
   SHA-256 is recomputed and compared against the value in the
   metadata. The benchmark CSV records both hashes (``sha256_original``
   and ``sha256_decrypted``) and a boolean ``hash_match`` column for
   every run, so the dissertation evaluation can show correctness
   directly from data.

The optional Ed25519 signature adds a third layer when present:
the recipient (or the ``--expect-signed-by`` flag) verifies that
the package was produced by the holder of a known signing key.

## 10. Temporary file handling

When the Audacity bridge exports a project, it writes a temporary
WAV to a per-call ``tempfile.TemporaryDirectory`` and overwrites
that file with zeros (followed by ``os.fsync`` and ``unlink``)
before returning. This is best-effort: on journalled, copy-on-write
or wear-levelled filesystems an in-place overwrite cannot guarantee
that no copy of the plaintext remains on the underlying storage.
The user manual mentions this honestly.

## 11. Limitations

* This is a dissertation prototype, not a production-ready security
  product, and has not been independently audited.
* It is a bridge-based Audacity plugin prototype; it is not a
  native C++ Audacity plug-in compiled inside Audacity.
* Recipients must protect their passphrases and private keys; once
  they decrypt a package, the audio is an ordinary WAV and the
  sender cannot technically prevent further redistribution.
* Secure deletion of temporary files is best-effort, especially on
  SSDs and copy-on-write filesystems.
* No cloud relay or revocable share links are implemented.

## 12. Dissertation implementation summary

The final prototype consists of a Python desktop application called
**SecureTrack** and an Audacity bridge component. The application
allows users to encrypt exported WAV files, decrypt secure packages,
and export audio directly from Audacity using the ``mod-script-pipe``
interface. Audio is encrypted locally before sharing using
AES-256-GCM, with Scrypt-based passphrase key derivation and SHA-256
integrity verification. The system produces a ``.securetrack``
package that can be distributed through normal channels while
keeping the audio content unreadable without the correct passphrase
or private key. Tamper detection and hash matching are recorded for
every benchmark run so the evaluation chapter can demonstrate
correctness and integrity directly from data.
