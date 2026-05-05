"""SecureTrack: prototype end-to-end encrypted track sharing for Audacity collaborators.

This package is the implementation artefact for a BSc Computing and Information
Technology dissertation at the University of Surrey. It provides a small
library and CLI that locally encrypts an exported WAV file into a portable
``.securetrack`` package that can be shared with a single intended
collaborator who knows the agreed passphrase.

Public modules:
    crypto           - AES-256-GCM AEAD (one-shot + chunked) + Scrypt + Ed25519.
    keys             - X25519 / Ed25519 keypair generation and PEM I/O.
    recipients       - Per-recipient wrapping of the content key.
    package          - ``.securetrack`` v2 package read/write helpers.
    metrics          - Pure helpers for size / throughput / hash metrics.
    benchmark        - Orchestrates a full encrypt/decrypt benchmark run.
    cli              - argparse-based command line interface.
    gui              - Tkinter GUI with progress bar and recipient picker.
    audacity_bridge  - mod-script-pipe driver and secure_export helper.
"""

from __future__ import annotations

__version__ = "1.0.0"
__all__ = ["__version__"]
