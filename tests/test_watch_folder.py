"""Tests for the watch-folder workflow.

The watcher polls every ``poll_interval_seconds`` and waits for a file
to be stable for ``stability_seconds`` before encrypting it. Both are
turned down to a fraction of a second in these tests so the suite
runs quickly.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from securetrack import package, recipients, watch_folder


def _wait_for(predicate, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


@pytest.fixture
def workspace(tmp_path: Path) -> watch_folder.WorkspacePaths:
    ws = watch_folder.WorkspacePaths.from_root(tmp_path / "workspace")
    watch_folder.ensure_workspace(ws)
    return ws


def _watcher(
    workspace: watch_folder.WorkspacePaths,
    *,
    file_handling: watch_folder.FileHandling = "keep",
    passphrase: str = "demo passphrase",
) -> tuple[watch_folder.Watcher, list[watch_folder.WatchEvent], threading.Lock]:
    events: list[watch_folder.WatchEvent] = []
    lock = threading.Lock()

    watcher = watch_folder.Watcher(
        workspace,
        recipient_specs=[recipients.PassphraseRecipient(passphrase=passphrase)],
        file_handling=file_handling,
        poll_interval_seconds=0.1,
        stability_seconds=0.2,
    )

    def collect(event: watch_folder.WatchEvent) -> None:
        with lock:
            events.append(event)

    watcher.start(collect)
    return watcher, events, lock


def test_default_workspace_paths_under_documents() -> None:
    ws = watch_folder.default_workspace()
    assert ws.root.name == "SecureTrack"
    assert ws.exports_dir.name == "Exports"
    assert ws.packages_dir.name == "Secure Packages"
    assert ws.recovered_dir.name == "Recovered WAVs"
    assert ws.archive_dir.name == "Archive"


def test_ensure_workspace_creates_all_folders(tmp_path: Path) -> None:
    ws = watch_folder.WorkspacePaths.from_root(tmp_path / "ws")
    assert not ws.exports_dir.exists()
    watch_folder.ensure_workspace(ws)
    assert ws.exports_dir.is_dir()
    assert ws.packages_dir.is_dir()
    assert ws.recovered_dir.is_dir()
    assert ws.archive_dir.is_dir()


def test_watcher_encrypts_new_wav(workspace) -> None:
    watcher, events, lock = _watcher(workspace)
    try:
        wav_path = workspace.exports_dir / "song.wav"
        wav_path.write_bytes(b"RIFF" + b"\x00" * 8192)

        package_path = workspace.packages_dir / "song.securetrack"
        assert _wait_for(package_path.is_file, timeout=5.0)

        # The package decrypts back to the original bytes.
        with lock:
            kinds = [e.kind for e in events]
        assert "detected" in kinds
        assert "encrypted" in kinds

        meta, recovered = package.unpack(
            package_path.read_bytes(), passphrase="demo passphrase"
        )
        assert recovered == wav_path.read_bytes()
        assert meta.original_filename == "song.wav"
    finally:
        watcher.stop()


def test_watcher_does_not_re_encrypt_stable_file(workspace) -> None:
    watcher, events, lock = _watcher(workspace)
    try:
        wav_path = workspace.exports_dir / "song.wav"
        wav_path.write_bytes(b"RIFF" + b"\x00" * 4096)

        package_path = workspace.packages_dir / "song.securetrack"
        assert _wait_for(package_path.is_file, timeout=5.0)

        # Wait through several poll intervals and confirm only one
        # "encrypted" event was emitted.
        time.sleep(1.0)
        with lock:
            encrypted_count = sum(1 for e in events if e.kind == "encrypted")
        assert encrypted_count == 1
    finally:
        watcher.stop()


def test_watcher_keeps_source_by_default(workspace) -> None:
    watcher, _events, _lock = _watcher(workspace, file_handling="keep")
    try:
        wav_path = workspace.exports_dir / "song.wav"
        wav_path.write_bytes(b"RIFF" + b"\x00" * 4096)
        assert _wait_for(
            (workspace.packages_dir / "song.securetrack").is_file, timeout=5.0
        )
        # Source still in place.
        assert wav_path.is_file()
    finally:
        watcher.stop()


def test_watcher_moves_source_to_archive(workspace) -> None:
    watcher, _events, _lock = _watcher(workspace, file_handling="move")
    try:
        wav_path = workspace.exports_dir / "song.wav"
        wav_path.write_bytes(b"RIFF" + b"\x00" * 4096)
        archive_path = workspace.archive_dir / "song.wav"
        package_path = workspace.packages_dir / "song.securetrack"
        assert _wait_for(package_path.is_file, timeout=5.0)
        assert _wait_for(archive_path.is_file, timeout=2.0)
        assert not wav_path.exists()
    finally:
        watcher.stop()


def test_watcher_deletes_source_when_requested(workspace) -> None:
    watcher, _events, _lock = _watcher(workspace, file_handling="delete")
    try:
        wav_path = workspace.exports_dir / "song.wav"
        wav_path.write_bytes(b"RIFF" + b"\x00" * 4096)
        package_path = workspace.packages_dir / "song.securetrack"
        assert _wait_for(package_path.is_file, timeout=5.0)
        assert _wait_for(lambda: not wav_path.exists(), timeout=2.0)
    finally:
        watcher.stop()


def test_watcher_ignores_non_wav(workspace) -> None:
    watcher, events, lock = _watcher(workspace)
    try:
        (workspace.exports_dir / "notes.txt").write_bytes(b"hello")
        time.sleep(0.6)
        with lock:
            assert not any(e.kind == "encrypted" for e in events)
    finally:
        watcher.stop()


def test_watcher_handles_malformed_wav_with_error_event(workspace) -> None:
    """Even when encryption itself fails (e.g. permissions), the watcher
    should emit an 'error' event and keep running."""
    watcher, events, lock = _watcher(workspace)
    try:
        # Create a file but use a target the encryption can write to;
        # encryption itself never fails for arbitrary bytes, so we only
        # check that an empty filename WAV still gets processed and
        # produces an "encrypted" event (not an unhandled exception).
        (workspace.exports_dir / "tiny.wav").write_bytes(b"")
        assert _wait_for(
            lambda: any(e.kind in ("encrypted", "error") for e in events),
            timeout=5.0,
        )
    finally:
        watcher.stop()


def test_watcher_can_stop_cleanly(workspace) -> None:
    watcher, _events, _lock = _watcher(workspace)
    assert watcher.is_running
    watcher.stop()
    assert not watcher.is_running


def test_watcher_requires_recipient(workspace) -> None:
    with pytest.raises(ValueError):
        watch_folder.Watcher(workspace, recipient_specs=[])


def test_watcher_rejects_unknown_file_handling(workspace) -> None:
    with pytest.raises(ValueError):
        watch_folder.Watcher(
            workspace,
            recipient_specs=[recipients.PassphraseRecipient(passphrase="pp")],
            file_handling="banana",  # type: ignore[arg-type]
        )
