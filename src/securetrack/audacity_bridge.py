"""Bridge between SecureTrack and Audacity's ``mod-script-pipe`` interface.

Audacity exposes a scripting interface that lets external programs
drive the running application. On POSIX this is a pair of named FIFOs
under ``$TMPDIR``; on Windows it is a pair of named pipes under
``\\\\.\\pipe\\``. The protocol is simple: each command is a UTF-8
string terminated by a newline, and Audacity replies with one or more
lines followed by either ``BatchCommand finished: OK`` or
``BatchCommand finished: Failed!`` and a trailing blank line.

Only a small subset of Audacity's commands is needed by the
prototype:

* ``Help: Command=Help`` — used as a no-op to confirm the pipe is
  connected to a real Audacity instance.
* ``Export2: Filename="<path>" NumChannels=2`` — exports the active
  project to a WAV at ``<path>``.

Two surfaces are exposed:

* :class:`AudacityScriptPipe` — a thin RAII wrapper around the pipe
  that can be unit-tested against fake FIFOs (see the corresponding
  test module).
* :func:`secure_export_from_audacity` — high-level helper that:
  drives Audacity to export a temporary WAV, encrypts that WAV into
  a ``.securetrack`` package, and securely deletes the temporary
  file before returning.

The bridge is **opt-in**: importing this module never tries to talk
to Audacity. A user must call :func:`detect_pipe_paths` /
:func:`AudacityScriptPipe.connect` explicitly.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import package, recipients

# --- pipe path resolution --------------------------------------------------

_POSIX_TO_NAME = "audacity_script_pipe.to.{uid}"
_POSIX_FROM_NAME = "audacity_script_pipe.from.{uid}"
_WIN_TO_NAME = r"\\.\pipe\ToSrvPipe"
_WIN_FROM_NAME = r"\\.\pipe\FromSrvPipe"

_DEFAULT_RESPONSE_TERMINATOR: str = "BatchCommand finished:"
_DEFAULT_TIMEOUT_SECONDS: float = 5.0


@dataclass(frozen=True)
class PipePaths:
    """Resolved Audacity pipe endpoints."""

    to_audacity: Path
    from_audacity: Path


def detect_pipe_paths(*, uid: int | None = None, tmpdir: Path | None = None) -> PipePaths:
    """Return the conventional pipe paths for the current user.

    On POSIX the default base directory is ``/tmp`` and the file names
    are ``audacity_script_pipe.{to,from}.<uid>``. On Windows the names
    are fixed and ``tmpdir`` / ``uid`` are ignored.

    The function does not check whether the paths exist; use
    :func:`is_audacity_pipe_available` for that.
    """
    if sys.platform.startswith("win"):
        return PipePaths(to_audacity=Path(_WIN_TO_NAME), from_audacity=Path(_WIN_FROM_NAME))
    base = Path(tmpdir) if tmpdir is not None else Path(tempfile.gettempdir())
    real_uid = uid if uid is not None else os.getuid()
    return PipePaths(
        to_audacity=base / _POSIX_TO_NAME.format(uid=real_uid),
        from_audacity=base / _POSIX_FROM_NAME.format(uid=real_uid),
    )


def is_audacity_pipe_available(paths: PipePaths | None = None) -> bool:
    """Return ``True`` if both pipe endpoints exist on disk.

    This is a cheap pre-flight check; a returned ``True`` does not
    guarantee that Audacity is actually listening — only that the
    files / pipes exist. Use :meth:`AudacityScriptPipe.ping` to
    confirm liveness.
    """
    paths = paths or detect_pipe_paths()
    return paths.to_audacity.exists() and paths.from_audacity.exists()


# --- pipe driver -----------------------------------------------------------


class AudacityPipeError(RuntimeError):
    """Raised when the script pipe cannot be reached or returns Failed."""


class AudacityScriptPipe:
    """Open ``mod-script-pipe`` and run commands against it.

    Use as a context manager::

        with AudacityScriptPipe.connect() as pipe:
            pipe.ping()
            pipe.export_wav(Path("/tmp/render.wav"))
    """

    def __init__(self, to_handle: IO[str], from_handle: IO[str]) -> None:
        self._to = to_handle
        self._from = from_handle

    # ---- construction ----------------------------------------------------

    @classmethod
    def connect(
        cls,
        paths: PipePaths | None = None,
        *,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    ) -> AudacityScriptPipe:
        paths = paths or detect_pipe_paths()
        if not paths.to_audacity.exists() or not paths.from_audacity.exists():
            raise AudacityPipeError(
                f"Audacity script pipe not found at {paths.to_audacity} / "
                f"{paths.from_audacity}. Make sure Audacity is running with "
                "mod-script-pipe enabled (Edit ▸ Preferences ▸ Modules)."
            )
        # Open the request side write-only, response side read-only. We
        # use line-buffered text mode to mirror Audacity's protocol.
        deadline = time.monotonic() + max(0.1, timeout_seconds)
        last_exc: OSError | None = None
        while time.monotonic() < deadline:
            try:
                to_handle = open(paths.to_audacity, mode="w", encoding="utf-8", buffering=1)
                from_handle = open(paths.from_audacity, mode="r", encoding="utf-8")
                return cls(to_handle, from_handle)
            except OSError as exc:  # pragma: no cover - environment dependent
                last_exc = exc
                time.sleep(0.1)
        raise AudacityPipeError(
            f"Could not open Audacity script pipe within {timeout_seconds:.1f}s: {last_exc}"
        )

    # ---- context manager -------------------------------------------------

    def __enter__(self) -> AudacityScriptPipe:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        for handle in (self._to, self._from):
            with suppress(Exception):
                handle.close()

    # ---- commands --------------------------------------------------------

    def send_command(
        self,
        command: str,
        *,
        terminator: str = _DEFAULT_RESPONSE_TERMINATOR,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    ) -> str:
        """Send a single command and return Audacity's response.

        On POSIX the command must end with a newline; we always append
        ``\\n`` here so callers can pass plain strings.
        """
        if "\n" in command:
            raise ValueError("commands must not contain embedded newlines")
        self._to.write(command + "\n")
        self._to.flush()
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
            line = self._from.readline()
            if not line:
                # End of stream while waiting for terminator.
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
        if "Failed" in response.splitlines()[-2:][0] if response.splitlines() else False:
            raise AudacityPipeError("Audacity reported failure for Help command.")
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
        # Audacity expects the path inside double quotes.
        command = f'Export2: Filename="{target_path}" NumChannels={int(num_channels)}'
        response = self.send_command(command, timeout_seconds=timeout_seconds)
        if "Failed" in response:
            raise AudacityPipeError(
                f"Audacity Export2 failed:\n{response.strip()}"
            )
        if not target_path.is_file():
            raise AudacityPipeError(
                f"Audacity claimed success but {target_path} was not created."
            )
        return target_path


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
    "secure_export_from_audacity",
]
