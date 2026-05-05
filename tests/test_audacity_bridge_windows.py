"""Windows-path tests for the Audacity bridge.

These tests run on POSIX too — they monkeypatch the platform sentinel
in ``audacity_bridge`` so we can exercise the Windows code path
without an actual Windows machine. The crucial property they verify
is that the existence check **does not** rely on
:meth:`pathlib.Path.exists` on Windows (because real
``\\\\.\\pipe\\*`` named pipes always report missing under
``Path.exists``).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from securetrack import audacity_bridge


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
    # We compare on the raw string components rather than ==Path(...)
    # because the test machine may be POSIX (where forward slashes
    # are kept).
    s_to = str(paths.to_audacity)
    s_from = str(paths.from_audacity)
    assert "ToSrvPipe" in s_to
    assert "FromSrvPipe" in s_from
    # The Windows pipe namespace is "\\.\pipe\..."; both endpoints
    # must contain the "pipe" namespace component.
    assert "pipe" in s_to and "pipe" in s_from


def test_is_available_uses_pywin32_path_when_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On Windows with pywin32, availability is decided by
    :func:`_windows_pipe_available_pywin32` and never touches
    :meth:`Path.exists`."""
    _force_windows(monkeypatch)
    _force_pywin32_present(monkeypatch)

    calls: list[str] = []

    def fake_pywin32_check(paths: audacity_bridge.PipePaths) -> bool:
        calls.append("pywin32")
        return True

    def fake_fallback(paths: audacity_bridge.PipePaths) -> bool:
        calls.append("fallback")
        return True

    def boom(self: Any) -> bool:
        calls.append("path.exists")
        raise AssertionError("Path.exists should not be called on Windows")

    monkeypatch.setattr(
        audacity_bridge, "_windows_pipe_available_pywin32", fake_pywin32_check
    )
    monkeypatch.setattr(
        audacity_bridge, "_windows_pipe_available_fallback", fake_fallback
    )
    monkeypatch.setattr(Path, "exists", boom)

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


def test_connect_raises_clear_error_when_pywin32_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without pywin32, the fallback connect attempt fails fast with a
    helpful message instead of silently succeeding."""
    _force_windows(monkeypatch)
    _force_pywin32_missing(monkeypatch)

    # Make the Windows fallback open() raise, simulating a real
    # missing-pipe situation.
    def fake_connect(paths: Any, timeout_seconds: float) -> Any:
        raise audacity_bridge.AudacityPipeError(
            "Could not open Audacity script pipe within 0.1s. Last error: "
            "[Errno 22] Invalid argument"
        )

    monkeypatch.setattr(audacity_bridge, "_connect_windows_fallback", fake_connect)

    with pytest.raises(audacity_bridge.AudacityPipeError) as info:
        audacity_bridge.AudacityScriptPipe.connect(_WINDOWS_PIPE_PATHS, timeout_seconds=0.1)
    assert "Could not open Audacity script pipe" in str(info.value)


def test_send_command_uses_windows_eol(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify that on Windows the command is suffixed with ``\\r\\n\\0`` to
    match what mod-script-pipe expects."""
    _force_windows(monkeypatch)
    monkeypatch.setattr(audacity_bridge, "_EOL", "\r\n\0")

    written: list[bytes] = []

    class FakeBackend:
        def write(self, data: bytes) -> None:
            written.append(data)

        def readline(self, timeout_seconds: float) -> str:
            # Make _read_response return immediately.
            return "BatchCommand finished: OK\n"

        def close(self) -> None:
            pass

    pipe = audacity_bridge.AudacityScriptPipe(FakeBackend())
    pipe.send_command("Help: Command=Help", timeout_seconds=0.5)

    assert written, "send_command should have written one frame"
    assert written[0].endswith(b"\r\n\0"), (
        f"expected Windows EOL, got: {written[0]!r}"
    )


def test_send_command_rejects_embedded_newlines(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeBackend:
        def write(self, data: bytes) -> None: ...
        def readline(self, timeout_seconds: float) -> str:
            return ""
        def close(self) -> None: ...

    pipe = audacity_bridge.AudacityScriptPipe(FakeBackend())
    with pytest.raises(ValueError):
        pipe.send_command("Help: Command=Help\n")
    with pytest.raises(ValueError):
        pipe.send_command("Help: Command=Help\r")
