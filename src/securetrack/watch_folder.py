"""Local watch-folder driver for SecureTrack.

Watches a folder for new ``.wav`` files, waits for each file to finish
being written, then encrypts it into a ``.securetrack`` package and
places the package in an output folder.

This module supports the simplest possible Audacity workflow::

    Audacity ── File ▸ Export ──► Documents/SecureTrack/Exports/
                                          │
                                          ▼  watcher detects a new WAV
                                  SecureTrack encrypt
                                          │
                                          ▼
                          Documents/SecureTrack/Secure Packages/

The watcher runs in a daemon background thread inside the GUI and
emits progress updates as :class:`WatchEvent` objects via a callback.
"""

from __future__ import annotations

import os
import shutil
import threading
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import package, recipients

#: Modes for what to do with the source WAV after a successful encryption.
FileHandling = Literal["keep", "delete", "move"]


# --- workspace paths -------------------------------------------------------


@dataclass(frozen=True)
class WorkspacePaths:
    """The set of folders SecureTrack uses for the local Audacity workflow."""

    root: Path
    exports_dir: Path
    packages_dir: Path
    recovered_dir: Path
    archive_dir: Path

    @classmethod
    def from_root(cls, root: Path) -> "WorkspacePaths":
        root = Path(root)
        return cls(
            root=root,
            exports_dir=root / "Exports",
            packages_dir=root / "Secure Packages",
            recovered_dir=root / "Recovered WAVs",
            archive_dir=root / "Archive",
        )


def default_workspace_root() -> Path:
    """The default workspace root (``~/Documents/SecureTrack``)."""
    return Path.home() / "Documents" / "SecureTrack"


def default_workspace() -> WorkspacePaths:
    return WorkspacePaths.from_root(default_workspace_root())


def ensure_workspace(workspace: WorkspacePaths) -> WorkspacePaths:
    """Create every folder in the workspace if it does not already exist."""
    for d in (
        workspace.root,
        workspace.exports_dir,
        workspace.packages_dir,
        workspace.recovered_dir,
        workspace.archive_dir,
    ):
        d.mkdir(parents=True, exist_ok=True)
    return workspace


# --- events ---------------------------------------------------------------


@dataclass(frozen=True)
class WatchEvent:
    """A single update from the watcher to the GUI / caller."""

    kind: str
    file: Path | None = None
    target: Path | None = None
    message: str = ""


EventCallback = Callable[[WatchEvent], None]


# --- watcher --------------------------------------------------------------


class Watcher:
    """Poll the exports folder and encrypt new WAV files as they appear.

    The watcher uses a simple stability heuristic: a file is only
    encrypted once its size has stayed unchanged for at least
    ``stability_seconds``. This avoids reading half-written WAVs that
    Audacity is still flushing to disk.
    """

    def __init__(
        self,
        workspace: WorkspacePaths,
        *,
        recipient_specs: list[recipients.RecipientSpec],
        signing_key: Ed25519PrivateKey | None = None,
        file_handling: FileHandling = "keep",
        poll_interval_seconds: float = 1.5,
        stability_seconds: float = 2.0,
    ) -> None:
        if not recipient_specs:
            raise ValueError("at least one recipient is required")
        if file_handling not in ("keep", "delete", "move"):
            raise ValueError(
                f"file_handling must be 'keep', 'delete' or 'move'; got {file_handling!r}"
            )
        self.workspace = workspace
        self.recipient_specs = recipient_specs
        self.signing_key = signing_key
        self.file_handling: FileHandling = file_handling
        self.poll_interval_seconds = poll_interval_seconds
        self.stability_seconds = stability_seconds

        self._known_sizes: dict[Path, int] = {}
        self._stable_since: dict[Path, float] = {}
        self._processed: set[tuple[str, int, float]] = set()

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # ---- public lifecycle -------------------------------------------------

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, on_event: EventCallback) -> None:
        """Start polling in a background daemon thread."""
        if self.is_running:
            return
        ensure_workspace(self.workspace)
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, args=(on_event,), name="securetrack-watcher", daemon=True
        )
        self._thread.start()

    def stop(self, *, timeout: float = 3.0) -> None:
        """Signal the background thread to exit and wait briefly for it."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        self._thread = None

    # ---- internal ---------------------------------------------------------

    def _run(self, on_event: EventCallback) -> None:
        on_event(
            WatchEvent(
                kind="started",
                message=f"Watching {self.workspace.exports_dir} for new WAV files.",
            )
        )
        try:
            while not self._stop_event.is_set():
                try:
                    self._scan(on_event)
                except Exception as exc:  # noqa: BLE001
                    on_event(WatchEvent(kind="error", message=str(exc)))
                self._stop_event.wait(self.poll_interval_seconds)
        finally:
            on_event(WatchEvent(kind="stopped", message="Watcher stopped."))

    def _scan(self, on_event: EventCallback) -> None:
        if not self.workspace.exports_dir.is_dir():
            return
        now = time.monotonic()
        for entry in self.workspace.exports_dir.iterdir():
            if entry.suffix.lower() != ".wav":
                continue
            try:
                stat = entry.stat()
            except OSError:
                continue
            sig = (str(entry), stat.st_size, stat.st_mtime)
            if sig in self._processed:
                continue
            prev_size = self._known_sizes.get(entry)
            if prev_size != stat.st_size:
                self._known_sizes[entry] = stat.st_size
                self._stable_since[entry] = now
                continue
            if now - self._stable_since.get(entry, now) < self.stability_seconds:
                continue
            self._process(entry, on_event, signature=sig)

    def _process(
        self,
        wav_path: Path,
        on_event: EventCallback,
        *,
        signature: tuple[str, int, float],
    ) -> None:
        on_event(WatchEvent(kind="detected", file=wav_path,
                            message=f"Detected {wav_path.name}."))
        package_path = self.workspace.packages_dir / (wav_path.stem + ".securetrack")
        on_event(WatchEvent(kind="encrypting", file=wav_path, target=package_path,
                            message=f"Encrypting {wav_path.name}…"))
        try:
            self.workspace.packages_dir.mkdir(parents=True, exist_ok=True)
            package.encrypt_file(
                wav_path,
                package_path,
                recipient_specs=self.recipient_specs,
                signing_key=self.signing_key,
            )
        except Exception as exc:  # noqa: BLE001
            on_event(
                WatchEvent(
                    kind="error",
                    file=wav_path,
                    message=f"Encryption failed for {wav_path.name}: {exc}",
                )
            )
            self._processed.add(signature)
            return

        on_event(
            WatchEvent(
                kind="encrypted",
                file=wav_path,
                target=package_path,
                message=f"Encrypted {wav_path.name} -> {package_path.name}",
            )
        )

        if self.file_handling == "delete":
            try:
                _secure_delete(wav_path)
                on_event(
                    WatchEvent(
                        kind="source-deleted",
                        file=wav_path,
                        message=f"Deleted {wav_path.name}.",
                    )
                )
            except OSError as exc:
                on_event(
                    WatchEvent(
                        kind="error",
                        file=wav_path,
                        message=f"Could not delete {wav_path.name}: {exc}",
                    )
                )
        elif self.file_handling == "move":
            self.workspace.archive_dir.mkdir(parents=True, exist_ok=True)
            archive_path = self.workspace.archive_dir / wav_path.name
            try:
                shutil.move(str(wav_path), str(archive_path))
                on_event(
                    WatchEvent(
                        kind="source-moved",
                        file=wav_path,
                        target=archive_path,
                        message=f"Moved {wav_path.name} to Archive.",
                    )
                )
            except OSError as exc:
                on_event(
                    WatchEvent(
                        kind="error",
                        file=wav_path,
                        message=f"Could not move {wav_path.name}: {exc}",
                    )
                )

        self._processed.add(signature)


# --- helpers --------------------------------------------------------------


def _secure_delete(path: Path) -> None:
    """Best-effort secure delete: zero the file then unlink."""
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
    "FileHandling",
    "WorkspacePaths",
    "WatchEvent",
    "Watcher",
    "default_workspace",
    "default_workspace_root",
    "ensure_workspace",
]
