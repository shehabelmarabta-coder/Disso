# Audacity Integration Notes (v2)

The v2 prototype now includes a real driver for Audacity's
``mod-script-pipe`` interface. This document captures how it works,
what is still missing, and the security caveats specific to the
integration.

## 1. Two integration modes

```
  Audacity project                      Audacity project
        │                                       │
        ▼ File ▸ Export ▸ Export as WAV         ▼ mod-script-pipe (Export2)
   exported.wav                           tmp/render.wav
        │                                       │
        ▼ python -m securetrack.cli encrypt    ▼ secure_export_from_audacity()
   share.securetrack                       share.securetrack
                                              │
                                              └─ tmp/render.wav is securely deleted
```

* **Manual workflow** — the user exports a WAV from Audacity by hand
  and runs SecureTrack on the resulting file. Works with every
  Audacity version, no prerequisites.
* **Bridge workflow** — the user calls
  ``securetrack.audacity_bridge.secure_export_from_audacity`` while
  Audacity is running with the *mod-script-pipe* module enabled.
  The bridge drives ``Export2`` over the script pipe, encrypts the
  resulting WAV and securely deletes the temporary plaintext.

## 2. Enabling mod-script-pipe

Audacity ships ``mod-script-pipe`` but it is **not** enabled by
default.

* *Edit ▸ Preferences ▸ Modules ▸ mod-script-pipe ▸ **Enabled***.
* Restart Audacity.

The pipe endpoints are then created at:

* POSIX: ``$TMPDIR/audacity_script_pipe.{to,from}.<uid>``
  (typically ``/tmp/audacity_script_pipe.{to,from}.<uid>``).
* Windows: ``\\.\pipe\ToSrvPipe`` and ``\\.\pipe\FromSrvPipe``.

``securetrack.audacity_bridge.detect_pipe_paths()`` resolves these
automatically; ``is_audacity_pipe_available()`` is a cheap pre-flight
check.

### 2.1 Windows-specific notes

Windows named pipes live in the NT object namespace, **not** on the
filesystem. As a consequence:

* ``pathlib.Path.exists()`` and ``os.path.exists()`` return ``False``
  for ``\\.\pipe\ToSrvPipe`` even when the pipe is live.
* Python's ``open(r"\\.\pipe\ToSrvPipe", "w", encoding=..., newline=...)``
  raises ``OSError: [Errno 22] Invalid argument`` because text-mode
  open does not understand the NT pipe namespace.

The bridge therefore uses **pywin32** on Windows to drive the pipes
through the native Win32 API:

* ``win32pipe.WaitNamedPipe`` for the existence check.
* ``win32file.CreateFile`` to open the handles.
* ``win32file.WriteFile`` / ``ReadFile`` / ``win32pipe.PeekNamedPipe``
  for non-blocking, timeout-aware reads.

pywin32 is declared as a conditional dependency in ``pyproject.toml``:

```
dependencies = [
    "cryptography>=41.0.0",
    "pywin32>=306; platform_system == 'Windows'",
]
```

so ``pip install -e ".[dev]"`` pulls it in automatically on Windows.
If pywin32 is missing the bridge falls back to a plain
``open()``-based driver that mirrors Audacity's own
``scripts/piped-work/pipe_test.py``. The fallback works in many
environments but cannot enforce read timeouts; the user is warned on
stderr that pywin32 is recommended.

The Windows protocol also uses a different end-of-line marker —
``\r\n\0`` (CRLF + NUL) instead of ``\n``. The bridge picks the right
EOL automatically.

## 3. Protocol cheat-sheet

The pipe is line-oriented and ASCII. Each command is a single line
followed by ``\n``. Audacity replies with one or more text lines
followed by either:

```
BatchCommand finished: OK
<blank line>
```

or:

```
BatchCommand finished: Failed!
<blank line>
```

The two commands the bridge currently uses:

| Command                                            | Purpose                          |
|----------------------------------------------------|----------------------------------|
| ``Help: Command=Help``                             | No-op liveness check (`ping()`). |
| ``Export2: Filename="<path>" NumChannels=<int>``   | Render the active project.       |

The bridge does not yet expose other commands such as
``GetInfo: Type=Tracks``; they would be straightforward additions.

## 3.1 CLI surface

Two SecureTrack subcommands wrap the bridge:

```
# Probe everything: pipe paths, detection, ping.
python -m securetrack.cli audacity-test

# Drive Audacity to export the active project, then encrypt the WAV
# in one go (temporary plaintext is overwritten and unlinked).
python -m securetrack.cli audacity-export \
    --recipient bob.pub.pem \
    --output    results/audacity_bridge_test.securetrack
```

``audacity-test`` is the recommended first step on a new machine.

## 4. Bridge API

```python
from pathlib import Path
from securetrack import keys, recipients
from securetrack.audacity_bridge import (
    AudacityScriptPipe,
    detect_pipe_paths,
    is_audacity_pipe_available,
    secure_export_from_audacity,
)

assert is_audacity_pipe_available()           # Audacity is running with the module enabled

# Low-level: drive the pipe yourself.
with AudacityScriptPipe.connect() as pipe:
    pipe.ping()
    pipe.export_wav(Path("/tmp/render.wav"))

# High-level: export, encrypt and securely delete in one call.
bob_pub = keys.load_x25519_public(Path("bob.pub.pem"))
secure_export_from_audacity(
    Path("share.securetrack"),
    recipient_specs=[recipients.PublicKeyRecipient(bob_pub)],
)
```

## 5. Security considerations

* **Temporary plaintext on disk.** ``secure_export_from_audacity``
  writes a temporary WAV under a per-call ``tempfile.TemporaryDirectory``
  and then calls ``_secure_delete`` (zero-overwrite + ``os.fsync`` +
  ``unlink``). On journalled filesystems, copy-on-write filesystems
  (Btrfs, ZFS, APFS) and SSDs with wear-levelling, the overwrite
  cannot guarantee that no copy of the plaintext remains. Sensitive
  workflows should run on encrypted filesystems.
* **Pipe authentication.** The script pipe is per-user but on a
  shared machine another local user with the same UID could attach
  to it. The bridge therefore performs a ``ping`` immediately after
  connecting and surfaces a clear error if the response is malformed.
* **Audacity version churn.** Audacity has shipped at least two
  variations of ``mod-script-pipe`` over its lifetime. The bridge is
  written against Audacity 3.5.x. If the response terminator changes
  in a future version, only ``_DEFAULT_RESPONSE_TERMINATOR`` in
  ``audacity_bridge.py`` needs updating.

## 6. Testing

Real Audacity is obviously not available in CI. ``tests/test_audacity_bridge.py``
exercises the driver against a pair of ``mkfifo`` FIFOs, with a
"fake Audacity" thread that mimics the response shape (multi-line
body terminated by ``BatchCommand finished: OK|Failed!``). This
covers the protocol parsing, command formatting and timeout paths.

Manual end-to-end testing against a real Audacity install is part of
the dissertation evaluation plan and will be reported in Chapter 5.

## 7. Backlog

1. ``GetInfo: Type=Tracks`` so the bridge can confirm the project is
   non-empty before exporting.
2. Per-track / per-stem export so a sender can address one package
   per stem to a different collaborator.
3. Nyquist plug-in front-end (one-click *Encrypt and share…* menu
   item that calls the Python bridge through a daemon).
4. Audacity 4 macro path once the new scripting interface is stable.
