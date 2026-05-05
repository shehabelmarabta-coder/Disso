# Packaging Notes

The dissertation prototype can be assessed directly from the
source code and a Python install. This document collects a few
lightweight options for running and (optionally) packaging the
application.

## 1. Run from source

```bash
python -m venv .venv
.venv\Scripts\activate           REM Windows
source .venv/bin/activate         # macOS / Linux

pip install -e ".[dev]"

python -m securetrack.gui         # desktop application
python -m securetrack.cli --help  # command line
```

This is the recommended path during development and is the way the
dissertation evaluation chapter was produced.

## 2. Windows launcher

``run_securetrack.bat`` in the project root opens the GUI using the
local virtual environment if ``.venv\`` exists, otherwise the system
Python on ``PATH``:

```bat
run_securetrack.bat
```

It is the simplest way to start the application on a Windows
laboratory machine without typing into a terminal.

## 3. Optional Windows executable (PyInstaller)

A single-file Windows executable can be produced with PyInstaller:

```bat
pip install pyinstaller
pyinstaller --noconfirm --windowed --onefile ^
    --name SecureTrack ^
    --collect-submodules cryptography ^
    --collect-submodules pywin32 ^
    -m securetrack.gui
```

The result lives at ``dist\SecureTrack.exe``.

### Limitations of the executable

* PyInstaller produces a comparatively large binary (≈ 30 MB)
  because the cryptography wheel and pywin32 are bundled in.
* On first launch Windows may take a few seconds to extract the
  bundle to a temporary directory.
* Microsoft Defender / SmartScreen sometimes flags freshly-built
  unsigned PyInstaller binaries until the machine has seen the file
  before; signing is not part of the dissertation scope.
* The executable runs only on the architecture and Windows version
  it was built on.

These limitations are why the dissertation submission references
the source code rather than relying on the bundled executable.

## 4. What to submit / reference

For the dissertation submission you only need the **source code**:

* this repository at the tagged dissertation version,
* a screenshot of ``pytest -v`` showing every test passing,
* the contents of ``results/benchmark_results.csv`` produced by
  ``securetrack benchmark``.

The optional executable is convenient for a live demo but is not
required for assessment.
