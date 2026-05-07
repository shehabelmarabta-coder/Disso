"""Long-term key management for SecureTrack v2.

Two key types are used:

* **X25519** keypairs are used to encrypt the per-package content key to
  one or more recipients. The sender encrypts to each recipient's public
  key; the recipient unwraps with their private key.
* **Ed25519** keypairs are used to sign the package metadata, recipient
  list and ciphertext digest, so a recipient can verify who created the
  package.

Keys are stored in standard PEM containers (``BEGIN PRIVATE KEY`` /
``BEGIN PUBLIC KEY``) so they can be inspected with ``openssl pkey``.
Private keys may optionally be encrypted with a passphrase at rest.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

KeyKind = Literal["x25519", "ed25519"]


# --- generation ------------------------------------------------------------


@dataclass(frozen=True)
class X25519Keypair:
    """A freshly generated X25519 keypair held in memory."""

    private_key: X25519PrivateKey
    public_key: X25519PublicKey


@dataclass(frozen=True)
class Ed25519Keypair:
    """A freshly generated Ed25519 signing keypair held in memory."""

    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey


def generate_x25519_keypair() -> X25519Keypair:
    """Generate a fresh X25519 keypair for content-key wrapping."""
    priv = X25519PrivateKey.generate()
    return X25519Keypair(private_key=priv, public_key=priv.public_key())


def generate_ed25519_keypair() -> Ed25519Keypair:
    """Generate a fresh Ed25519 keypair for package signing."""
    priv = Ed25519PrivateKey.generate()
    return Ed25519Keypair(private_key=priv, public_key=priv.public_key())


# --- raw byte access -------------------------------------------------------


def x25519_public_bytes(public_key: X25519PublicKey) -> bytes:
    """Return the 32 raw bytes of an X25519 public key."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def x25519_private_bytes(private_key: X25519PrivateKey) -> bytes:
    """Return the 32 raw bytes of an X25519 private key (handle with care)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def ed25519_public_bytes(public_key: Ed25519PublicKey) -> bytes:
    """Return the 32 raw bytes of an Ed25519 public key."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def x25519_public_from_bytes(raw: bytes) -> X25519PublicKey:
    """Reconstruct an X25519 public key from its 32 raw bytes."""
    return X25519PublicKey.from_public_bytes(raw)


def ed25519_public_from_bytes(raw: bytes) -> Ed25519PublicKey:
    """Reconstruct an Ed25519 public key from its 32 raw bytes."""
    return Ed25519PublicKey.from_public_bytes(raw)


# --- PEM I/O ---------------------------------------------------------------


def _private_pem(
    private_key: X25519PrivateKey | Ed25519PrivateKey,
    *,
    passphrase: str | None,
) -> bytes:
    enc: serialization.KeySerializationEncryption
    if passphrase:
        enc = serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
    else:
        enc = serialization.NoEncryption()
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )


def _public_pem(public_key: X25519PublicKey | Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def write_keypair(
    keypair: X25519Keypair | Ed25519Keypair,
    *,
    private_path: Path,
    public_path: Path,
    passphrase: str | None = None,
) -> None:
    """Write a keypair to two PEM files (``priv.pem`` / ``pub.pem``).

    Parent directories are created if needed. The private key file is
    written with mode ``0o600`` to discourage casual exposure.
    """
    private_path = Path(private_path)
    public_path = Path(public_path)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    private_path.write_bytes(_private_pem(keypair.private_key, passphrase=passphrase))
    try:
        private_path.chmod(0o600)
    except (OSError, NotImplementedError):  # pragma: no cover - Windows fallback
        pass
    public_path.write_bytes(_public_pem(keypair.public_key))


def load_x25519_private(path: Path, passphrase: str | None = None) -> X25519PrivateKey:
    """Load an X25519 private key from a PEM file."""
    pw = passphrase.encode("utf-8") if passphrase else None
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=pw)
    if not isinstance(key, X25519PrivateKey):
        raise ValueError(f"{path} does not contain an X25519 private key")
    return key


def load_x25519_public(path: Path) -> X25519PublicKey:
    """Load an X25519 public key from a PEM file."""
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, X25519PublicKey):
        raise ValueError(f"{path} does not contain an X25519 public key")
    return key


def load_ed25519_private(path: Path, passphrase: str | None = None) -> Ed25519PrivateKey:
    """Load an Ed25519 signing key from a PEM file."""
    pw = passphrase.encode("utf-8") if passphrase else None
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=pw)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} does not contain an Ed25519 private key")
    return key


def load_ed25519_public(path: Path) -> Ed25519PublicKey:
    """Load an Ed25519 verification key from a PEM file."""
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"{path} does not contain an Ed25519 public key")
    return key


# --- convenience helper used by the GUI's "Generate Key Pair" button -------


def generate_x25519_keypair_to(
    folder: Path,
    name: str,
    *,
    private_passphrase: str | None = None,
) -> tuple[Path, Path]:
    """Generate an X25519 keypair and write the two PEM files into ``folder``.

    Args:
        folder: Folder in which the two files are written. Created if missing.
        name: Base name used for the files. ``"collaborator_key"`` produces
            ``collaborator_key_public.pem`` and ``collaborator_key_private.pem``.
        private_passphrase: Optional passphrase used to encrypt the private
            key file at rest (PKCS#8 best-available encryption).

    Returns:
        ``(public_path, private_path)``.
    """
    if not name or not name.strip():
        raise ValueError("key name must not be empty")
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    public_path = folder / f"{name}_public.pem"
    private_path = folder / f"{name}_private.pem"
    keypair = generate_x25519_keypair()
    write_keypair(
        keypair,
        private_path=private_path,
        public_path=public_path,
        passphrase=private_passphrase,
    )
    return public_path, private_path


__all__ = [
    "KeyKind",
    "X25519Keypair",
    "Ed25519Keypair",
    "generate_x25519_keypair",
    "generate_ed25519_keypair",
    "x25519_public_bytes",
    "x25519_private_bytes",
    "ed25519_public_bytes",
    "x25519_public_from_bytes",
    "ed25519_public_from_bytes",
    "write_keypair",
    "load_x25519_private",
    "load_x25519_public",
    "load_ed25519_private",
    "load_ed25519_public",
    "generate_x25519_keypair_to",
]
