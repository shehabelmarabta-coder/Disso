"""Manual end-to-end test for the SecureTrack <-> Audacity bridge.

Run this **with Audacity already open and mod-script-pipe enabled**
(*Edit ▸ Preferences ▸ Modules ▸ mod-script-pipe ▸ Enabled*, then
restart Audacity).

On Windows, install pywin32 first:

    pip install pywin32

Then run:

    python examples/audacity_pipe_test.py

The script prints:

1. The pipe paths SecureTrack expects to find.
2. Whether each pipe is detectable.
3. The result of sending ``Help: Command=Help`` over the pipe.

Exit codes
----------
* 0 — everything worked.
* 1 — pipes not detected.
* 2 — pipes detected but the bridge could not connect or Audacity
       did not reply within the timeout.
"""

from __future__ import annotations

import sys

from securetrack import audacity_bridge


def main() -> int:
    print("== SecureTrack Audacity bridge — manual smoke test ==")
    print()

    paths = audacity_bridge.detect_pipe_paths()
    print("detect_pipe_paths():")
    print(f"  to:   {paths.to_audacity}")
    print(f"  from: {paths.from_audacity}")
    print()

    print("runtime_status():")
    for k, v in audacity_bridge.runtime_status().items():
        print(f"  {k:<20s}: {v}")
    print()

    available = audacity_bridge.is_audacity_pipe_available(paths)
    print(f"is_audacity_pipe_available(): {available}")
    print()

    if not available:
        print("Pipes not detected.")
        print("Make sure Audacity is running with mod-script-pipe enabled")
        print("(Edit ▸ Preferences ▸ Modules ▸ mod-script-pipe ▸ Enabled).")
        print("On Windows also make sure pywin32 is installed:")
        print("    pip install pywin32")
        return 1

    print("Connecting and sending: Help: Command=Help")
    try:
        with audacity_bridge.AudacityScriptPipe.connect(timeout_seconds=5.0) as pipe:
            response = pipe.ping()
    except audacity_bridge.AudacityPipeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print()
    print("---- Audacity response ----")
    sys.stdout.write(response)
    if not response.endswith("\n"):
        print()
    print("---------------------------")
    print()
    print("OK: the SecureTrack <-> Audacity bridge is working.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
