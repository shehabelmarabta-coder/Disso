# Audacity Integration Notes

The first prototype is intentionally **not** a native Audacity plug-in.
This document records the integration path that the dissertation
proposes and that future iterations of the code will follow.

## 1. Where SecureTrack sits today

The current build operates on files **after** they have been exported
from Audacity. The user flow is:

```
  Audacity project
        │  File ▸ Export ▸ Export as WAV
        ▼
   exported.wav  ──►  python -m securetrack.cli encrypt ─►  share.securetrack
                                                                │
                                                                ▼
                                              <user-chosen transport>
                                                                │
                                                                ▼
   recovered.wav ◄──  python -m securetrack.cli decrypt  ◄──  share.securetrack
        │
        ▼  File ▸ Open
  Audacity project
```

This matches Audacity's existing workflow and requires no changes to
the DAW itself. It is the right place to start because it lets the
dissertation focus on the cryptographic core.

## 2. Planned native integration paths

There are three credible ways to make SecureTrack feel like an
Audacity feature rather than a separate tool. They are listed in
ascending order of engineering effort.

### 2.1 `mod-script-pipe` (preferred next step)

Audacity exposes a scripting interface called
[mod-script-pipe](https://manual.audacityteam.org/man/scripting.html)
that listens on a named pipe / FIFO and accepts commands such as
``Export2: Filename="..." NumChannels=2``.

Intended driver in ``audacity_bridge.py``:

```text
1.  Resolve pipe paths:
       POSIX:   $TMPDIR/audacity_script_pipe.{to,from}.<uid>
       Windows: \\.\pipe\{ToSrvPipe,FromSrvPipe}
2.  Open both endpoints.
3.  Send: Export2: Filename="<tmp>/securetrack.wav" NumChannels=2
4.  Read responses until the line "BatchCommand finished: OK".
5.  Hand the resulting path to package.encrypt_file(...).
6.  Securely delete the temporary WAV.
```

This is a small, well-bounded engineering task — most of the
complexity is correct error handling and securely deleting the
temporary plaintext file.

### 2.2 Nyquist / macro plug-in

Audacity supports Nyquist plug-ins for in-app menu items. A thin
`.ny` file could:

1. Trigger an in-place export to a temporary WAV.
2. Shell out to ``python -m securetrack.cli encrypt`` via the Nyquist
   ``system`` function, or to a small daemon already running.

This gives a one-click experience inside Audacity but inherits the
limitation that ``system`` is platform-specific and the user must
have Python installed.

### 2.3 Compiled module / fork

The most invasive option is to ship a fork of Audacity (or an
out-of-tree C++ module) that calls libsodium / OpenSSL directly.
This is a much larger engineering effort and is **not** recommended
for the dissertation timeline. It is mentioned only because Audacity
itself ships some experimental modules under ``modules/``.

## 3. Security considerations specific to integration

* **Temporary plaintext on disk.** Any path that exports through
  Audacity first writes a plaintext WAV to a temporary location.
  The integration code must delete this file (and ideally overwrite
  it with random bytes first) before returning. Rely on
  ``tempfile.NamedTemporaryFile(delete=True)`` in a context manager.
* **Pipe authentication.** The script pipe is per-user, but on a
  shared machine another local user could in principle attach to
  it. The dissertation should note this limitation explicitly.
* **Audacity update churn.** ``mod-script-pipe`` has changed name
  and location across Audacity versions. The integration code
  should target a specific Audacity release (currently 3.5.x) and
  surface a clear error if the pipe cannot be found.

## 4. What ``audacity_bridge.py`` looks like today

The module exposes three function stubs that document the intended
public surface:

```python
is_audacity_pipe_available() -> bool
export_current_project_audio(target_path: Path) -> Path
secure_export_from_audacity(target_package: Path,
                            passphrase: str,
                            *, labels: dict[str, str] | None = None) -> Path
```

All three currently raise ``NotImplementedError`` so that nobody
mistakes the prototype for a working plug-in. They will be filled
in once the cryptographic core is stable and the dissertation moves
to the integration milestone.
