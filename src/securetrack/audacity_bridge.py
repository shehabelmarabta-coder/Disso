"""Bridge between SecureTrack and Audacity's ``mod-script-pipe`` interface.

Audacity exposes a scripting interface over a pair of named pipes:

* **POSIX** (Linux / macOS): FIFOs at
  ``$TMPDIR/audacity_script_pipe.{to,from}.<uid>``. These are real
  filesystem entries and Python's built-in ``open()`` works against
  them.
* **Windows**: kernel named pipes at
  ``\\\\.\\pipe\\ToSrvPipe`` and ``\\\\.\\pipe\\FromSrvPipe``. These
  live in the NT object namespace, **not** on the filesystem, so
  ``pathlib.Path.exists()`` always returns ``False`` for them and
  ``open(..., encoding=..., newline=...)`` typically fails with
  ``OSError: [Errno 22] Invalid argument``. The correct Windows
  client uses ``CreateFile`` / ``ReadFile`` / ``WriteFile`` from
  ``pywin32``.

This module therefore picks one of three backends at runtime:

1. POSIX FIFO backend (``_PosixBackend``).
2. Windows pywin32 backend (``_WindowsPywin32Backend``) — preferred.
3. Windows fallback backend (``_WindowsFallbackBackend``) — used only
   if pywin32 is missing. Mirrors the simple ``open()``-based driver
   that ships with Audacity at ``scripts/piped-work/pipe_test.py``;
   it works in many environments but cannot enforce read timeouts.

Two surfaces are exposed:

* :class:`AudacityScriptPipe` — RAII pipe wrapper that can be unit
  tested against fake FIFOs.
* :func:`secure_export_from_audacity` — high-level helper that drives
  Audacity to export a temporary WAV, encrypts that WAV into a
  ``.securetrack`` package, then securely deletes the temporary
  plaintext.
"""

from __future__ import annotations

import os
import platform
import sys
import tempfile
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import package, recipients

# --- platform detection ----------------------------------------------------

_IS_WINDOWS: bool = sys.platform.startswith("win") or platform.system() == "Windows"

# Try to import pywin32 on Windows. Failure is *not* fatal at import
# time — we want ``securetrack.cli`` to keep working for
# encrypt/decrypt even on a Windows box without pywin32. The bridge
# itself reports the missing dependency only when actually used.
_HAS_PYWIN32: bool = False
_PYWIN32_IMPORT_ERROR: ImportError | None = None
_win32file: Any = None
_win32pipe: Any = None
_pywintypes: Any = None
if _IS_WINDOWS:
    try:  # pragma: no cover - only exercised on Windows
        import pywintypes as _pywintypes  # type: ignore
        import win32file as _win32file  # type: ignore
        import win32pipe as _win32pipe  # type: ignore

        _HAS_PYWIN32 = True
    except ImportError as _exc:  # pragma: no cover
        _PYWIN32_IMPORT_ERROR = _exc


# --- pipe path resolution --------------------------------------------------

_POSIX_TO_NAME = "audacity_script_pipe.to.{uid}"
_POSIX_FROM_NAME = "audacity_script_pipe.from.{uid}"
_WIN_TO_NAME = r"\\.\pipe\ToSrvPipe"
_WIN_FROM_NAME = r"\\.\pipe\FromSrvPipe"

_DEFAULT_RESPONSE_TERMINATOR: str = "BatchCommand finished:"
_DEFAULT_TIMEOUT_SECONDS: float = 5.0

# Audacity's protocol uses a different end-of-line on Windows. This
# matches the official `scripts/piped-work/pipe_test.py` shipped with
# Audacity. ``\0`` is a NUL byte that Audacity Windows uses as part
# of the terminator.
_EOL: str = "\r\n\0" if _IS_WINDOWS else "\n"


@dataclass(frozen=True)
class PipePaths:
    """Resolved Audacity pipe endpoints."""

    to_audacity: Path
    from_audacity: Path


def detect_pipe_paths(*, uid: int | None = None, tmpdir: Path | None = None) -> PipePaths:
    """Return the conventional pipe paths for the current user / platform."""
    if _IS_WINDOWS:
        return PipePaths(
            to_audacity=Path(_WIN_TO_NAME),
            from_audacity=Path(_WIN_FROM_NAME),
        )
    base = Path(tmpdir) if tmpdir is not None else Path(tempfile.gettempdir())
    real_uid = uid if uid is not None else os.getuid()
    return PipePaths(
        to_audacity=base / _POSIX_TO_NAME.format(uid=real_uid),
        from_audacity=base / _POSIX_FROM_NAME.format(uid=real_uid),
    )


def is_audacity_pipe_available(paths: PipePaths | None = None) -> bool:
    """Return ``True`` if both pipe endpoints exist and look reachable.

    POSIX uses :meth:`Path.exists` because FIFOs are real filesystem
    entries. Windows uses :func:`win32pipe.WaitNamedPipe` (when
    pywin32 is installed) because named pipes live in the NT object
    namespace and ``Path.exists`` always reports them as missing. If
    pywin32 is not installed, we attempt a tentative
    :func:`open` against the pipe and report success based on that.
    """
    paths = paths or detect_pipe_paths()
    if _IS_WINDOWS:
        if _HAS_PYWIN32:
            return _windows_pipe_available_pywin32(paths)
        return _windows_pipe_available_fallback(paths)
    return paths.to_audacity.exists() and paths.from_audacity.exists()


def _windows_pipe_available_pywin32(paths: PipePaths) -> bool:  # pragma: no cover
    try:
        _win32pipe.WaitNamedPipe(str(paths.to_audacity), 50)
        _win32pipe.WaitNamedPipe(str(paths.from_audacity), 50)
        return True
    except _pywintypes.error:
        return False


def _windows_pipe_available_fallback(paths: PipePaths) -> bool:  # pragma: no cover
    # We cannot reliably probe a Windows pipe without pywin32, so we
    # try the simplest possible open() (matching Audacity's own
    # pipe_test.py) and report success if it works.
    try:
        h = open(str(paths.to_audacity), "w")
        h.close()
        return True
    except OSError:
        return False


def runtime_status() -> dict[str, str]:
    """Return a small dict describing the current bridge configuration.

    Useful for the ``securetrack audacity-test`` CLI command and
    end-user troubleshooting. Never includes secret data.
    """
    paths = detect_pipe_paths()
    status: dict[str, str] = {
        "platform": "windows" if _IS_WINDOWS else "posix",
        "to_pipe": str(paths.to_audacity),
        "from_pipe": str(paths.from_audacity),
        "pywin32_installed": "yes" if _HAS_PYWIN32 else ("no" if _IS_WINDOWS else "n/a"),
    }
    if _PYWIN32_IMPORT_ERROR is not None:
        status["pywin32_error"] = str(_PYWIN32_IMPORT_ERROR)
    status["available"] = "yes" if is_audacity_pipe_available(paths) else "no"
    return status


# --- backend protocol + implementations ------------------------------------


class _PipeBackend(Protocol):
    def write(self, data: bytes) -> None: ...
    def readline(self, timeout_seconds: float) -> str: ...
    def close(self) -> None: ...


class _PosixBackend:
    """Plain-file backend over POSIX FIFOs."""

    def __init__(self, to_handle: IO[str], from_handle: IO[str]) -> None:
        self._to = to_handle
        self._from = from_handle

    def write(self, data: bytes) -> None:
        self._to.write(data.decode("utf-8"))
        self._to.flush()

    def readline(self, timeout_seconds: float) -> str:
        # Text-mode readline blocks until a line is available; the
        # outer ``_read_response`` deadline still applies because we
        # hold the protocol-level deadline there.
        return self._from.readline()

    def close(self) -> None:
        for h in (self._to, self._from):
            with suppress(Exception):
                h.close()


class _WindowsPywin32Backend:
    """Windows backend using pywin32 directly.

    Reads are non-blocking via :func:`win32pipe.PeekNamedPipe`, so we
    can implement a real per-line timeout.
    """

    def __init__(self, to_handle: Any, from_handle: Any) -> None:  # pragma: no cover
        self._to = to_handle
        self._from = from_handle
        self._read_buffer = b""

    def write(self, data: bytes) -> None:  # pragma: no cover
        _win32file.WriteFile(self._to, data)

    def readline(self, timeout_seconds: float) -> str:  # pragma: no cover
        deadline = time.monotonic() + max(0.05, timeout_seconds)
        while True:
            nl_idx = self._read_buffer.find(b"\n")
            if nl_idx >= 0:
                line_bytes = self._read_buffer[: nl_idx + 1]
                self._read_buffer = self._read_buffer[nl_idx + 1 :]
                # Strip stray NUL bytes Audacity emits as part of the
                # Windows EOL marker.
                return line_bytes.decode("utf-8", errors="replace").replace("\x00", "")
            try:
                _, n_avail, _ = _win32pipe.PeekNamedPipe(self._from, 0)
            except _pywintypes.error as exc:
                raise OSError(f"PeekNamedPipe failed: {exc}") from exc
            if n_avail > 0:
                _, data = _win32file.ReadFile(self._from, n_avail)
                self._read_buffer += data
                continue
            if time.monotonic() > deadline:
                raise TimeoutError(f"timed out after {timeout_seconds:.1f}s")
            time.sleep(0.05)

    def close(self) -> None:  # pragma: no cover
        for h in (self._to, self._from):
            with suppress(Exception):
                _win32file.CloseHandle(h)


class _WindowsFallbackBackend:
    """Windows fallback that mirrors Audacity's own pipe_test.py."""

    def __init__(self, to_handle: IO[str], from_handle: IO[str]) -> None:  # pragma: no cover
        self._to = to_handle
        self._from = from_handle

    def write(self, data: bytes) -> None:  # pragma: no cover
        self._to.write(data.decode("utf-8"))
        self._to.flush()

    def readline(self, timeout_seconds: float) -> str:  # pragma: no cover
        # No way to apply a timeout without pywin32; this just blocks.
        line = self._from.readline()
        return line.replace("\x00", "") if line else line

    def close(self) -> None:  # pragma: no cover
        for h in (self._to, self._from):
            with suppress(Exception):
                h.close()


# --- AudacityScriptPipe ---------------------------------------------------


class AudacityPipeError(RuntimeError):
    """Raised when the script pipe cannot be reached or returns Failed."""


class AudacityScriptPipe:
    """Open ``mod-script-pipe`` and run commands against it.

    Use as a context manager::

        with AudacityScriptPipe.connect() as pipe:
            pipe.ping()
            pipe.export_wav(Path("C:/tmp/render.wav"))
    """

    def __init__(self, backend: _PipeBackend) -> None:
        self._backend = backend

    # ---- construction ----------------------------------------------------

    @classmethod
    def connect(
        cls,
        paths: PipePaths | None = None,
        *,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    ) -> AudacityScriptPipe:
        paths = paths or detect_pipe_paths()
        if _IS_WINDOWS:
            backend = _connect_windows(paths, timeout_seconds)
        else:
            backend = _connect_posix(paths, timeout_seconds)
        return cls(backend)

    # ---- context manager -------------------------------------------------

    def __enter__(self) -> AudacityScriptPipe:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        self._backend.close()

    # ---- commands --------------------------------------------------------

    def send_command(
        self,
        command: str,
        *,
        terminator: str = _DEFAULT_RESPONSE_TERMINATOR,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    ) -> str:
        """Send a single command and return Audacity's response."""
        if "\n" in command or "\r" in command:
            raise ValueError("commands must not contain embedded newlines")
        try:
            self._backend.write((command + _EOL).encode("utf-8"))
        except OSError as exc:
            raise AudacityPipeError(f"write to Audacity pipe failed: {exc}") from exc
        return self._read_response(terminator=terminator, timeout_seconds=timeout_seconds)

    def _read_response(
        self,
        *,
        terminator: str,
        timeout_seconds: float,
    ) -> str:
        deadline = time.monotonic() + max(0.1, timeout_seconds)
        lines: list[str] = []
        while True:
            if time.monotonic() > deadline:
                raise AudacityPipeError(
                    f"Timed out after {timeout_seconds:.1f}s waiting for response."
                )
            try:
                remaining = max(0.1, deadline - time.monotonic())
                line = self._backend.readline(remaining)
            except TimeoutError as exc:
                raise AudacityPipeError(str(exc)) from exc
            except OSError as exc:
                raise AudacityPipeError(f"read from Audacity pipe failed: {exc}") from exc
            if not line:
                if lines:
                    raise AudacityPipeError(
                        "Pipe closed before response terminator was seen."
                    )
                continue
            lines.append(line)
            if line.startswith(terminator):
                break
        return "".join(lines)

    def ping(self) -> str:
        """Send a no-op command to confirm Audacity is listening."""
        response = self.send_command("Help: Command=Help")
        # The Help command should always succeed; if Audacity reports
        # Failed, surface that as an explicit pipe error.
        for line in response.splitlines():
            if line.startswith(_DEFAULT_RESPONSE_TERMINATOR) and "Failed" in line:
                raise AudacityPipeError(f"Audacity Help command failed:\n{response.strip()}")
        return response

    def export_wav(
        self,
        target_path: Path,
        *,
        num_channels: int = 2,
        timeout_seconds: float = 60.0,
    ) -> Path:
        """Drive Audacity to export the active project to ``target_path`` as WAV."""
        target_path = Path(target_path).resolve()
        target_path.parent.mkdir(parents=True, exist_ok=True)
        command = f'Export2: Filename="{target_path}" NumChannels={int(num_channels)}'
        response = self.send_command(command, timeout_seconds=timeout_seconds)
        if "Failed" in response:
            raise AudacityPipeError(f"Audacity Export2 failed:\n{response.strip()}")
        if not target_path.is_file():
            raise AudacityPipeError(
                f"Audacity claimed success but {target_path} was not created."
            )
        return target_path


# --- per-platform connect helpers -----------------------------------------


def _connect_posix(paths: PipePaths, timeout_seconds: float) -> _PipeBackend:
    if not paths.to_audacity.exists() or not paths.from_audacity.exists():
        raise AudacityPipeError(
            f"Audacity script pipe not found at {paths.to_audacity} / "
            f"{paths.from_audacity}. Make sure Audacity is running with "
            "mod-script-pipe enabled (Edit ▸ Preferences ▸ Modules)."
        )
    deadline = time.monotonic() + max(0.1, timeout_seconds)
    last_exc: OSError | None = None
    while time.monotonic() < deadline:
        try:
            to_handle = open(paths.to_audacity, mode="w", encoding="utf-8", buffering=1)
            from_handle = open(paths.from_audacity, mode="r", encoding="utf-8")
            return _PosixBackend(to_handle, from_handle)
        except OSError as exc:  # pragma: no cover - environment dependent
            last_exc = exc
            time.sleep(0.1)
    raise AudacityPipeError(  # pragma: no cover
        f"Could not open Audacity script pipe within {timeout_seconds:.1f}s: {last_exc}"
    )


def _connect_windows(paths: PipePaths, timeout_seconds: float) -> _PipeBackend:
    if _HAS_PYWIN32:
        return _connect_windows_pywin32(paths, timeout_seconds)
    return _connect_windows_fallback(paths, timeout_seconds)


def _connect_windows_pywin32(paths: PipePaths, timeout_seconds: float) -> _PipeBackend:  # pragma: no cover
    deadline = time.monotonic() + max(0.1, timeout_seconds)
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            to_handle = _win32file.CreateFile(
                str(paths.to_audacity),
                _win32file.GENERIC_WRITE,
                0,
                None,
                _win32file.OPEN_EXISTING,
                0,
                None,
            )
        except _pywintypes.error as exc:
            last_exc = exc
            # ERROR_PIPE_BUSY (231): wait a moment for an instance.
            if getattr(exc, "winerror", None) == 231:
                with suppress(_pywintypes.error):
                    _win32pipe.WaitNamedPipe(str(paths.to_audacity), 1000)
            time.sleep(0.1)
            continue
        try:
            from_handle = _win32file.CreateFile(
                str(paths.from_audacity),
                _win32file.GENERIC_READ,
                0,
                None,
                _win32file.OPEN_EXISTING,
                0,
                None,
            )
        except _pywintypes.error as exc:
            with suppress(Exception):
                _win32file.CloseHandle(to_handle)
            last_exc = exc
            time.sleep(0.1)
            continue
        return _WindowsPywin32Backend(to_handle, from_handle)
    raise AudacityPipeError(
        f"Could not connect to Audacity script pipe within {timeout_seconds:.1f}s. "
        "Make sure Audacity is running with mod-script-pipe enabled "
        "(Edit ▸ Preferences ▸ Modules ▸ mod-script-pipe ▸ Enabled). "
        f"Last error: {last_exc}"
    )


def _connect_windows_fallback(paths: PipePaths, timeout_seconds: float) -> _PipeBackend:  # pragma: no cover
    if _PYWIN32_IMPORT_ERROR is not None:
        sys.stderr.write(
            "warning: pywin32 is not installed; SecureTrack will fall back to a\n"
            "         less reliable pipe driver that cannot enforce timeouts.\n"
            "         Install pywin32 with `pip install pywin32` for the\n"
            "         recommended Windows behaviour.\n"
        )
    deadline = time.monotonic() + max(0.1, timeout_seconds)
    last_exc: OSError | None = None
    while time.monotonic() < deadline:
        try:
            # Match Audacity's own pipe_test.py: plain open(), no encoding,
            # no newline argument (those break on Windows named pipes).
            to_handle = open(str(paths.to_audacity), "w")
            from_handle = open(str(paths.from_audacity), "rt")
            return _WindowsFallbackBackend(to_handle, from_handle)
        except OSError as exc:
            last_exc = exc
            time.sleep(0.1)
    raise AudacityPipeError(
        f"Could not open Audacity script pipe within {timeout_seconds:.1f}s. "
        "Make sure Audacity is running with mod-script-pipe enabled. "
        f"Last error: {last_exc}"
    )


# --- high-level helper -----------------------------------------------------


def secure_export_from_audacity(
    target_package: Path,
    *,
    recipient_specs: list[recipients.RecipientSpec],
    labels: dict[str, str] | None = None,
    creator: dict[str, str] | None = None,
    signing_key: Ed25519PrivateKey | None = None,
    pipe_paths: PipePaths | None = None,
    num_channels: int = 2,
) -> Path:
    """Export the current Audacity project and seal the WAV in a package.

    The temporary WAV is created in a per-call temp directory and is
    securely deleted (overwritten with zeros, then unlinked) before
    this function returns, regardless of success or failure.
    """
    target_package = Path(target_package)
    target_package.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="securetrack-") as tmp_dir:
        tmp_wav = Path(tmp_dir) / "render.wav"
        try:
            with AudacityScriptPipe.connect(pipe_paths) as pipe:
                pipe.ping()
                pipe.export_wav(tmp_wav, num_channels=num_channels)

            package.encrypt_file(
                tmp_wav,
                target_package,
                recipient_specs=recipient_specs,
                labels=labels,
                creator=creator,
                signing_key=signing_key,
            )
        finally:
            _secure_delete(tmp_wav)

    return target_package


def _secure_delete(path: Path) -> None:
    """Overwrite a file with zeros and unlink it, ignoring errors.

    This is a *best effort* defence; on many filesystems (journalled,
    copy-on-write, SSD with wear-levelling) overwriting in place does
    not reliably erase data. The dissertation discusses this caveat.
    """
    if not path.is_file():
        return
    with suppress(OSError):
        size = path.stat().st_size
        with path.open("r+b") as fh:
            chunk = b"\x00" * 65536
            remaining = size
            while remaining > 0:
                fh.write(chunk[: min(len(chunk), remaining)])
                remaining -= min(len(chunk), remaining)
            fh.flush()
            os.fsync(fh.fileno())
    with suppress(OSError):
        path.unlink()


__all__ = [
    "AudacityPipeError",
    "AudacityScriptPipe",
    "PipePaths",
    "detect_pipe_paths",
    "is_audacity_pipe_available",
    "runtime_status",
    "secure_export_from_audacity",
]
