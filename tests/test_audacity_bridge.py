"""Unit tests for the Audacity script-pipe driver.

Real Audacity is not available in CI, so these tests exercise the
driver against a pair of FIFOs that we drive ourselves from a
"fake Audacity" thread. This is enough to verify the protocol
parsing, command formatting and timeout handling.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

from securetrack import audacity_bridge


pytestmark = pytest.mark.skipif(
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
    """Run a tiny request/response loop in a thread until ``stop`` is set."""
    # Open the request side for reading; opening blocks until the
    # client opens the write side, and vice versa.
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


def test_detect_pipe_paths_posix(tmp_path: Path) -> None:
    paths = audacity_bridge.detect_pipe_paths(uid=1234, tmpdir=tmp_path)
    assert str(paths.to_audacity).endswith("audacity_script_pipe.to.1234")
    assert str(paths.from_audacity).endswith("audacity_script_pipe.from.1234")


def test_is_available_false_when_pipes_missing(tmp_path: Path) -> None:
    paths = audacity_bridge.detect_pipe_paths(uid=12345, tmpdir=tmp_path)
    assert audacity_bridge.is_audacity_pipe_available(paths) is False


def test_ping_against_fake_audacity(tmp_path: Path) -> None:
    paths = _make_fifos(tmp_path)
    stop = threading.Event()

    def handler(cmd: str) -> str:
        if cmd.startswith("Help:"):
            return "Available commands: Export2 Help\nBatchCommand finished: OK\n\n"
        return "Unknown command\nBatchCommand finished: Failed!\n\n"

    server = threading.Thread(
        target=_fake_audacity, args=(paths,), kwargs={"handler": handler, "stop": stop},
        daemon=True,
    )
    server.start()
    try:
        with audacity_bridge.AudacityScriptPipe.connect(paths) as pipe:
            response = pipe.ping()
            assert "Available commands" in response
    finally:
        stop.set()
        # Open and close the FIFOs so the fake server can return.
        with open(paths.to_audacity, "w"):
            pass
        server.join(timeout=2)


def test_export_wav_against_fake_audacity(tmp_path: Path) -> None:
    paths = _make_fifos(tmp_path)
    target = tmp_path / "render.wav"
    stop = threading.Event()

    def handler(cmd: str) -> str:
        if cmd.startswith("Export2:"):
            # Pretend Audacity wrote a WAV file at the requested path.
            assert f'Filename="{target}"' in cmd
            target.write_bytes(b"RIFF")  # minimal placeholder
            return "Exported.\nBatchCommand finished: OK\n\n"
        return "Help text.\nBatchCommand finished: OK\n\n"

    server = threading.Thread(
        target=_fake_audacity, args=(paths,), kwargs={"handler": handler, "stop": stop},
        daemon=True,
    )
    server.start()
    try:
        with audacity_bridge.AudacityScriptPipe.connect(paths) as pipe:
            result = pipe.export_wav(target, num_channels=2)
            assert result == target.resolve()
            assert target.read_bytes().startswith(b"RIFF")
    finally:
        stop.set()
        with open(paths.to_audacity, "w"):
            pass
        server.join(timeout=2)


def test_export_wav_fails_when_audacity_says_failed(tmp_path: Path) -> None:
    paths = _make_fifos(tmp_path)
    target = tmp_path / "render.wav"
    stop = threading.Event()

    def handler(cmd: str) -> str:
        return "Sorry.\nBatchCommand finished: Failed!\n\n"

    server = threading.Thread(
        target=_fake_audacity, args=(paths,), kwargs={"handler": handler, "stop": stop},
        daemon=True,
    )
    server.start()
    try:
        with audacity_bridge.AudacityScriptPipe.connect(paths) as pipe:
            with pytest.raises(audacity_bridge.AudacityPipeError):
                pipe.export_wav(target)
    finally:
        stop.set()
        with open(paths.to_audacity, "w"):
            pass
        server.join(timeout=2)


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


# ``time`` is imported above to keep the FIFO blocking semantics
# obvious in some platforms; suppress unused-import lint without
# losing the import for future test additions.
_ = time
