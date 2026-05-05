@echo off
REM ----------------------------------------------------------------------
REM SecureTrack launcher for Windows.
REM
REM Runs the SecureTrack desktop application using the local virtual
REM environment if one exists at .venv\, otherwise falls back to the
REM system Python on PATH.
REM ----------------------------------------------------------------------

if exist .venv\Scripts\python.exe (
    .venv\Scripts\python.exe -m securetrack.gui
) else (
    python -m securetrack.gui
)
