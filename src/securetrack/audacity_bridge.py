"""Placeholder bridge between SecureTrack and Audacity.

This module is **not** a working Audacity plugin. It is a documented
placeholder that captures the intended integration path so that a later
iteration of the project can fill in the implementation.

Two integration paths are anticipated:

1. **External export workflow (current prototype).**
   The user exports their audio from Audacity manually
   (``File → Export → Export as WAV``) and then runs SecureTrack via
   the CLI or GUI. This is what the dissertation skeleton implements.

2. **Native Audacity scripting via ``mod-script-pipe``.**
   Audacity ships with a scripting interface called
   `mod-script-pipe <https://manual.audacityteam.org/man/scripting.html>`_
   that exposes commands such as ``Export2`` over a named pipe / FIFO.
   A future version of SecureTrack can drive this pipe to ask Audacity
   to render the current project to a temporary WAV, then pass that
   file straight into :func:`securetrack.package.encrypt_file`. The
   stubs below show the intended public surface.

3. **Nyquist plug-in (longer term).**
   Audacity also supports Nyquist plug-ins for in-app menu items.
   A thin Nyquist front-end could call out to a Python helper via
   ``system`` once the pipe-based path is proven.

The functions in this module raise :class:`NotImplementedError` and
exist only so that callers (and the dissertation reader) can see the
intended API shape.
"""

from __future__ import annotations

from pathlib import Path

# The default name of the script pipe under POSIX systems. On Windows it
# is exposed as ``\\.\pipe\ToSrvPipe`` and ``\\.\pipe\FromSrvPipe``.
_POSIX_TO_PIPE = Path("/tmp/audacity_script_pipe.to.<uid>")  # noqa: ERA001 - documentation
_POSIX_FROM_PIPE = Path("/tmp/audacity_script_pipe.from.<uid>")  # noqa: ERA001


def is_audacity_pipe_available() -> bool:
    """Return ``True`` if Audacity's scripting pipe appears to be running.

    .. note::
       Not yet implemented. A real implementation must:

       * Resolve the per-user pipe paths (``$TMPDIR/audacity_script_pipe.*``
         on POSIX, ``\\\\.\\pipe\\ToSrvPipe`` on Windows).
       * Check that both endpoints exist and can be opened non-blockingly.
       * Optionally send a no-op ``Help: Command=Help`` and read the
         response to confirm Audacity is actually listening.
    """
    raise NotImplementedError("Audacity pipe detection is not yet implemented.")


def export_current_project_audio(target_path: Path) -> Path:
    """Ask Audacity to export the active project to ``target_path`` as WAV.

    .. note::
       Not yet implemented. Intended sequence::

           1. Open the script pipe.
           2. Send: ``Export2: Filename="<target>" NumChannels=2``
           3. Wait for the ``BatchCommand finished: OK`` response.
           4. Return ``target_path``.

       The dissertation prototype side-steps this by asking the user
       to use ``File → Export`` manually.
    """
    raise NotImplementedError("Audacity export bridge is not yet implemented.")


def secure_export_from_audacity(
    target_package: Path,
    passphrase: str,
    *,
    labels: dict[str, str] | None = None,
) -> Path:
    """End-to-end helper: export from Audacity then encrypt the result.

    .. note::
       Not yet implemented. The intended flow is:

       1. ``wav_path = export_current_project_audio(temp_wav)``
       2. ``package.encrypt_file(wav_path, target_package, passphrase, labels=labels)``
       3. Securely delete the temporary WAV.

       For the first prototype, users should run the export step manually
       in Audacity and then call :func:`securetrack.package.encrypt_file`
       (or the ``securetrack encrypt`` CLI command) directly.
    """
    raise NotImplementedError(
        "Native Audacity integration is not yet implemented; "
        "export the file from Audacity manually and use the CLI / GUI for now."
    )


__all__ = [
    "is_audacity_pipe_available",
    "export_current_project_audio",
    "secure_export_from_audacity",
]
