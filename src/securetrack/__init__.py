"""SecureTrack: prototype end-to-end encrypted track sharing for Audacity collaborators.

This package is the implementation artefact for a BSc Computing and Information
Technology dissertation at the University of Surrey. It provides a small
library and CLI that locally encrypts an exported WAV file into a portable
``.securetrack`` package that can be shared with a single intended
collaborator who knows the agreed passphrase.

Public modules:
    crypto           - AES-256-GCM authenticated encryption + Scrypt KDF.
    package          - ``.securetrack`` package format read/write helpers.
    metrics          - Pure helpers for size / throughput / hash metrics.
    benchmark        - Orchestrates a full encrypt/decrypt benchmark run.
    cli              - argparse-based command line interface.
    gui              - Minimal Tkinter GUI skeleton.
    audacity_bridge  - Placeholder for future Audacity integration.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
