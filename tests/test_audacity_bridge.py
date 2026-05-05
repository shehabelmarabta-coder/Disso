"""Tests for the SecureTrack <-> Audacity bridge.

POSIX systems test the real driver against a pair of ``mkfifo`` FIFOs
with a "fake Audacity" thread. Windows-specific code paths are
exercised on POSIX too via ``monkeypatch``: we flip the
``_IS_WINDOWS`` / ``_HAS_PYWIN32`` sentinels and check that the
existence test, send-command EOL and connect path all do the right
thing without ever calling :meth:`pathlib.Path.exists` (which is
unreliable for Windows named pipes).
"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

from securetrack import audacity_bridge


# =============================================================================
# POSIX FIFO tests (skipped on Windows)
# =============================================================================

posix_only = pytest.mark.skipif(
    sys.platform.startswith("win"),
    reason="FIFO-based fake-Audacity tests are POSIX-only.",
)


def _make_fifos(tmp_path: Path) -> audacity_bridge.PipePaths:
    to_path = tmp_path / "to"
    from_path = tmp_path / "from"
    os.mkfifo(to_path)
    os.mkfifo(from_path)
    return audacity_bridge.PipePaths(to_audacity=to_path, from_audacity=from_path)


def _fake_audacity(
    paths: audacity_bridge.PipePaths,
    *,
    handler,
    stop: threading.Event,
) -> None:
    """Tiny request/response loop in a background thread."""
    with open(paths.to_audacity, "r", encoding="utf-8") as inbound, \
         open(paths.from_audacity, "w", encoding="utf-8", buffering=1) as outbound:
        while not stop.is_set():
            line = inbound.readline()
            if not line:
                break
            response = handler(line.strip())
            outbound.write(response)
            outbound.flush()
            if "BatchCommand finished:" not in response:
                outbound.write("BatchCommand finished: OK\n\n")
                outbound.flush()


def _drain_server(stop: threading.Event, paths: audacity_bridge.PipePaths,
                  server: threading.Thread) -> None:
    stop.set()
    with open(paths.to_audacity, "w"):
        pass
    server.join(timeout=2)


# --- POSIX path detection -------------------------------------------------


@posix_only
def test_detect_pipe_paths_posix(tmp_path: Path) -> None:
    paths = audacity_bridge.detect_pipe_paths(uid=1234, tmpdir=tmp_path)
    assert str(paths.to_audacity).endswith("audacity_script_pipe.to.1234")
    assert str(paths.from_audacity).endswith("audacity_script_pipe.from.1234")


@posix_only
def test_is_available_false_when_pipes_missing(tmp_path: Path) -> None:
    paths = audacity_bridge.detect_pipe_paths(uid=12345, tmpdir=tmp_path)
    assert audacity_bridge.is_audacity_pipe_available(paths) is False


# --- POSIX FIFO ping ------------------------------------------------------


@posix_only
def test_ping_against_fake_audacity(tmp_path: Path) -> None:
    paths = _make_fifos(tmp_path)
    stop = threading.Event()

    def handler(cmd: str) -> str:
        if cmd.startswith("Help:"):
            return "Available commands: SelectAll Export2 Help\nBatchCommand finished: OK\n\n"
        return "Unknown\nBatchCommand finished: Failed!\n\n"

    server = threading.Thread(
        target=_fake_audacity, args=(paths,),
        kwargs={"handler": handler, "stop": stop}, daemon=True,
    )
    server.start()
    try:
        with audacity_bridge.AudacityScriptPipe.connect(paths) as pipe:
            response = pipe.ping()
            assert "Available commands" in response
    finally:
        _drain_server(stop, paths, server)


# --- POSIX FIFO export with SelectAll + min-size check -------------------


@posix_only
def test_export_wav_sends_select_all_and_export2(tmp_path: Path) -> None:
    paths = _make_fifos(tmp_path)
    target = tmp_path / "render.wav"
    stop = threading.Event()
    seen_commands: list[str] = []

    def handler(cmd: str) -> str:
        seen_commands.append(cmd)
        if cmd.startswith("SelectAll"):
            return "Selected.\nBatchCommand finished: OK\n\n"
        if cmd.startswith("Export2:"):
            target.write_bytes(b"RIFF" + b"\x00" * 4096)  # > 1024 bytes
            return "Exported.\nBatchCommand finished: OK\n\n"
        return "Unknown\nBatchCommand finished: Failed!\n\n"

    server = threading.Thread(
        target=_fake_audacity, args=(paths,),
        kwargs={"handler": handler, "stop": stop}, daemon=True,
    )
    server.start()
    try:
        with audacity_bridge.AudacityScriptPipe.connect(paths) as pipe:
            result = pipe.export_wav(target, num_channels=2)
            assert result == target.resolve()
            assert seen_commands[0].startswith("SelectAll")
            assert any(c.startswith("Export2:") for c in seen_commands)
    finally:
        _drain_server(stop, paths, server)


@posix_only
def test_export_wav_skips_select_all_when_disabled(tmp_path: Path) -> None:
    paths = _make_fifos(tmp_path)
    target = tmp_path / "render.wav"
    stop = threading.Event()
    seen_commands: list[str] = []

    def handler(cmd: str) -> str:
        seen_commands.append(cmd)
        if cmd.startswith("Export2:"):
            target.write_bytes(b"RIFF" + b"\x00" * 4096)
            return "Exported.\nBatchCommand finished: OK\n\n"
        return "Help.\nBatchCommand finished: OK\n\n"

    server = threading.Thread(
        target=_fake_audacity, args=(paths,),
        kwargs={"handler": handler, "stop": stop}, daemon=True,
    )
    server.start()
    try:
        with audacity_bridge.AudacityScriptPipe.connect(paths) as pipe:
            pipe.export_wav(target, select_all=False)
            assert not any(c.startswith("SelectAll") for c in seen_commands)
            assert any(c.startswith("Export2:") for c in seen_commands)
    finally:
        _drain_server(stop, paths, server)


@posix_only
def test_export_wav_rejects_empty_export(tmp_path: Path) -> None:
    paths = _make_fifos(tmp_path)
    target = tmp_path / "render.wav"
    stop = threading.Event()

    def handler(cmd: str) -> str:
        if cmd.startswith("SelectAll"):
            return "Selected.\nBatchCommand finished: OK\n\n"
        if cmd.startswith("Export2:"):
            target.write_bytes(b"RIFF" + b"\x00" * 8)  # only 12 bytes
            return "Exported.\nBatchCommand finished: OK\n\n"
        return "?.\nBatchCommand finished: OK\n\n"

    server = threading.Thread(
        target=_fake_audacity, args=(paths,),
        kwargs={"handler": handler, "stop": stop}, daemon=True,
    )
    server.start()
    try:
        with audacity_bridge.AudacityScriptPipe.connect(paths) as pipe:
            with pytest.raises(audacity_bridge.AudacityPipeError) as info:
                pipe.export_wav(target)
            assert "empty or near-empty" in str(info.value)
    finally:
        _drain_server(stop, paths, server)


@posix_only
def test_export_wav_fails_when_audacity_says_failed(tmp_path: Path) -> None:
    paths = _make_fifos(tmp_path)
    target = tmp_path / "render.wav"
    stop = threading.Event()

    def handler(cmd: str) -> str:
        return "Sorry.\nBatchCommand finished: Failed!\n\n"

    server = threading.Thread(
        target=_fake_audacity, args=(paths,),
        kwargs={"handler": handler, "stop": stop}, daemon=True,
    )
    server.start()
    try:
        with audacity_bridge.AudacityScriptPipe.connect(paths) as pipe:
            with pytest.raises(audacity_bridge.AudacityPipeError):
                pipe.export_wav(target)
    finally:
        _drain_server(stop, paths, server)


@posix_only
def test_connect_raises_when_pipe_missing(tmp_path: Path) -> None:
    missing = audacity_bridge.PipePaths(
        to_audacity=tmp_path / "nope.to", from_audacity=tmp_path / "nope.from"
    )
    with pytest.raises(audacity_bridge.AudacityPipeError):
        audacity_bridge.AudacityScriptPipe.connect(missing, timeout_seconds=0.1)


def test_secure_delete_removes_file(tmp_path: Path) -> None:
    p = tmp_path / "secret.bin"
    p.write_bytes(b"top secret payload")
    audacity_bridge._secure_delete(p)
    assert not p.exists()


# =============================================================================
# Windows-path tests (run on POSIX too via monkeypatch)
# =============================================================================


_WINDOWS_PIPE_PATHS = audacity_bridge.PipePaths(
    to_audacity=Path(r"\\.\pipe\ToSrvPipe"),
    from_audacity=Path(r"\\.\pipe\FromSrvPipe"),
)


def _force_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(audacity_bridge, "_IS_WINDOWS", True)


def _force_pywin32_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(audacity_bridge, "_HAS_PYWIN32", False)
    monkeypatch.setattr(audacity_bridge, "_PYWIN32_IMPORT_ERROR", ImportError("test"))


def _force_pywin32_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(audacity_bridge, "_HAS_PYWIN32", True)
    monkeypatch.setattr(audacity_bridge, "_PYWIN32_IMPORT_ERROR", None)


def test_detect_pipe_paths_returns_windows_names_when_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_windows(monkeypatch)
    paths = audacity_bridge.detect_pipe_paths()
    s_to = str(paths.to_audacity)
    s_from = str(paths.from_audacity)
    assert "ToSrvPipe" in s_to
    assert "FromSrvPipe" in s_from
    assert "pipe" in s_to and "pipe" in s_from


def test_is_available_uses_pywin32_path_when_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On Windows with pywin32, availability never touches Path.exists."""
    _force_windows(monkeypatch)
    _force_pywin32_present(monkeypatch)

    calls: list[str] = []
    monkeypatch.setattr(
        audacity_bridge, "_windows_pipe_available_pywin32",
        lambda paths: calls.append("pywin32") or True,
    )
    monkeypatch.setattr(
        audacity_bridge, "_windows_pipe_available_fallback",
        lambda paths: calls.append("fallback") or True,
    )
    monkeypatch.setattr(
        Path, "exists", lambda self: (_ for _ in ()).throw(
            AssertionError("Path.exists should not be called on Windows")
        ),
    )
    assert audacity_bridge.is_audacity_pipe_available(_WINDOWS_PIPE_PATHS) is True
    assert calls == ["pywin32"]


def test_is_available_uses_fallback_when_pywin32_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_windows(monkeypatch)
    _force_pywin32_missing(monkeypatch)
    monkeypatch.setattr(
        audacity_bridge, "_windows_pipe_available_fallback", lambda paths: True
    )

    def boom(self: Any) -> bool:
        raise AssertionError("Path.exists should not be called on Windows")

    monkeypatch.setattr(Path, "exists", boom)
    assert audacity_bridge.is_audacity_pipe_available(_WINDOWS_PIPE_PATHS) is True


def test_is_available_returns_false_when_check_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_windows(monkeypatch)
    _force_pywin32_missing(monkeypatch)
    monkeypatch.setattr(
        audacity_bridge, "_windows_pipe_available_fallback", lambda paths: False
    )
    assert audacity_bridge.is_audacity_pipe_available(_WINDOWS_PIPE_PATHS) is False


def test_runtime_status_includes_pywin32_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_windows(monkeypatch)
    _force_pywin32_missing(monkeypatch)
    monkeypatch.setattr(
        audacity_bridge, "_windows_pipe_available_fallback", lambda paths: False
    )
    status = audacity_bridge.runtime_status()
    assert status["platform"] == "windows"
    assert status["pywin32_installed"] == "no"
    assert status["available"] == "no"
    assert "ToSrvPipe" in status["to_pipe"]
    assert "FromSrvPipe" in status["from_pipe"]
    assert "test" in status.get("pywin32_error", "")


def test_send_command_uses_windows_eol(monkeypatch: pytest.MonkeyPatch) -> None:
    """Commands on Windows must end with ``\\r\\n\\0`` to match
    Audacity's mod-script-pipe protocol."""
    _force_windows(monkeypatch)
    monkeypatch.setattr(audacity_bridge, "_EOL", "\r\n\0")

    written: list[bytes] = []

    class FakeBackend:
        def write(self, data: bytes) -> None:
            written.append(data)

        def readline(self, timeout_seconds: float) -> str:
            return "BatchCommand finished: OK\n"

        def close(self) -> None: ...

    pipe = audacity_bridge.AudacityScriptPipe(FakeBackend())
    pipe.send_command("Help: Command=Help", timeout_seconds=0.5)
    assert written and written[0].endswith(b"\r\n\0")


def test_send_command_rejects_embedded_newlines() -> None:
    class FakeBackend:
        def write(self, data: bytes) -> None: ...
        def readline(self, timeout_seconds: float) -> str: return ""
        def close(self) -> None: ...

    pipe = audacity_bridge.AudacityScriptPipe(FakeBackend())
    with pytest.raises(ValueError):
        pipe.send_command("Help: Command=Help\n")
    with pytest.raises(ValueError):
        pipe.send_command("Help: Command=Help\r")
