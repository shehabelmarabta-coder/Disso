"""Per-recipient wrapping of the SecureTrack content key.

A v2 ``.securetrack`` package has a single random 256-bit *content
key* that encrypts the audio. The ``recipients.json`` member lists
one entry per intended recipient, each of which contains an
independently wrapped copy of that content key. A package can be
addressed to:

* one or more **passphrase** recipients (``type = "passphrase"``)
  — the content key is wrapped under a key derived from the
  passphrase via Scrypt;
* one or more **public-key** recipients
  (``type = "pubkey"``, ``kind = "x25519"``) — the sender performs
  an X25519 ECDH against the recipient's long-term public key using
  a fresh ephemeral private key, runs the shared secret through
  HKDF, and AES-GCM-encrypts the content key under the resulting
  wrapping key.

Mixing both types in a single package is supported: the recipient
who attempts decryption simply tries the entries that match their
input (passphrase / private key) and the first one that authenticates
yields the content key.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import crypto, keys

#: Passed as ``info`` to HKDF so the wrapping key is bound to its purpose.
HKDF_INFO_X25519: bytes = b"securetrack-x25519-wrap-v2"


# --- recipient specifications (input to pack) ------------------------------


@dataclass(frozen=True)
class PassphraseRecipient:
    """Recipient that will unwrap the content key with a passphrase."""

    passphrase: str
    label: str | None = None


@dataclass(frozen=True)
class PublicKeyRecipient:
    """Recipient that will unwrap the content key with their X25519 private key."""

    public_key: X25519PublicKey
    label: str | None = None


RecipientSpec = PassphraseRecipient | PublicKeyRecipient


# --- wrapped entry (what ends up in recipients.json) -----------------------


@dataclass
class WrappedRecipient:
    """A single entry in ``recipients.json``.

    The same dataclass represents both kinds of entries; fields that do
    not apply to a given ``type`` are left as :data:`None`.
    """

    type: str  # "passphrase" | "pubkey"
    kind: str | None  # "scrypt" for passphrase; "x25519" for pubkey
    wrap_nonce: bytes
    wrapped_key: bytes
    salt: bytes | None = None  # passphrase only
    recipient_pubkey: bytes | None = None  # pubkey only
    ephemeral_pubkey: bytes | None = None  # pubkey only
    label: str | None = None

    # ---- (de)serialisation ------------------------------------------------

    def to_json_obj(self) -> dict[str, Any]:
        obj: dict[str, Any] = {
            "type": self.type,
            "wrap_nonce": _b64(self.wrap_nonce),
            "wrapped_key": _b64(self.wrapped_key),
        }
        if self.kind is not None:
            obj["kind"] = self.kind
        if self.label is not None:
            obj["label"] = self.label
        if self.salt is not None:
            obj["salt"] = _b64(self.salt)
        if self.recipient_pubkey is not None:
            obj["recipient_pubkey"] = _b64(self.recipient_pubkey)
        if self.ephemeral_pubkey is not None:
            obj["ephemeral_pubkey"] = _b64(self.ephemeral_pubkey)
        return obj

    @classmethod
    def from_json_obj(cls, obj: dict[str, Any]) -> WrappedRecipient:
        try:
            t = str(obj["type"])
            wrap_nonce = base64.b64decode(obj["wrap_nonce"])
            wrapped_key = base64.b64decode(obj["wrapped_key"])
        except (KeyError, ValueError) as exc:
            raise ValueError(f"recipient entry is malformed: {exc}") from exc
        kind = str(obj["kind"]) if "kind" in obj else None
        label = str(obj["label"]) if "label" in obj else None
        salt = base64.b64decode(obj["salt"]) if "salt" in obj else None
        recipient_pubkey = (
            base64.b64decode(obj["recipient_pubkey"])
            if "recipient_pubkey" in obj
            else None
        )
        ephemeral_pubkey = (
            base64.b64decode(obj["ephemeral_pubkey"])
            if "ephemeral_pubkey" in obj
            else None
        )
        return cls(
            type=t,
            kind=kind,
            wrap_nonce=wrap_nonce,
            wrapped_key=wrapped_key,
            salt=salt,
            recipient_pubkey=recipient_pubkey,
            ephemeral_pubkey=ephemeral_pubkey,
            label=label,
        )


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


# --- wrap / unwrap helpers -------------------------------------------------


def wrap_for_passphrase(
    content_key: bytes,
    passphrase: str,
    *,
    aad: bytes,
    label: str | None = None,
) -> WrappedRecipient:
    """Wrap ``content_key`` so it can be unwrapped by ``passphrase``."""
    salt = crypto.generate_salt()
    wrap_key = crypto.derive_key(passphrase, salt)
    wrap_nonce = crypto.generate_nonce()
    wrapped = AESGCM(wrap_key).encrypt(wrap_nonce, content_key, aad)
    return WrappedRecipient(
        type="passphrase",
        kind="scrypt",
        wrap_nonce=wrap_nonce,
        wrapped_key=wrapped,
        salt=salt,
        label=label,
    )


def wrap_for_pubkey(
    content_key: bytes,
    recipient_public: X25519PublicKey,
    *,
    aad: bytes,
    label: str | None = None,
) -> WrappedRecipient:
    """Wrap ``content_key`` so it can be unwrapped by the recipient's X25519 key."""
    ephemeral_priv = X25519PrivateKey.generate()
    ephemeral_pub = ephemeral_priv.public_key()
    shared = ephemeral_priv.exchange(recipient_public)

    recipient_raw = keys.x25519_public_bytes(recipient_public)
    ephemeral_raw = keys.x25519_public_bytes(ephemeral_pub)
    wrap_key = crypto.hkdf_derive_key(
        shared,
        info=HKDF_INFO_X25519 + b"|" + ephemeral_raw + b"|" + recipient_raw,
    )
    wrap_nonce = crypto.generate_nonce()
    wrapped = AESGCM(wrap_key).encrypt(wrap_nonce, content_key, aad)
    return WrappedRecipient(
        type="pubkey",
        kind="x25519",
        wrap_nonce=wrap_nonce,
        wrapped_key=wrapped,
        recipient_pubkey=recipient_raw,
        ephemeral_pubkey=ephemeral_raw,
        label=label,
    )


def wrap_for_recipients(
    content_key: bytes,
    specs: list[RecipientSpec],
    *,
    aad: bytes,
) -> list[WrappedRecipient]:
    """Wrap ``content_key`` for each recipient specification."""
    if not specs:
        raise ValueError("at least one recipient is required")
    out: list[WrappedRecipient] = []
    for spec in specs:
        if isinstance(spec, PassphraseRecipient):
            out.append(
                wrap_for_passphrase(
                    content_key, spec.passphrase, aad=aad, label=spec.label
                )
            )
        elif isinstance(spec, PublicKeyRecipient):
            out.append(
                wrap_for_pubkey(
                    content_key, spec.public_key, aad=aad, label=spec.label
                )
            )
        else:  # pragma: no cover - exhaustively covered above
            raise TypeError(f"unsupported recipient spec: {type(spec).__name__}")
    return out


def unwrap_with_passphrase(
    entry: WrappedRecipient,
    passphrase: str,
    *,
    aad: bytes,
) -> bytes:
    if entry.type != "passphrase" or entry.kind != "scrypt" or entry.salt is None:
        raise ValueError("entry is not a passphrase recipient")
    wrap_key = crypto.derive_key(passphrase, entry.salt)
    try:
        return AESGCM(wrap_key).decrypt(entry.wrap_nonce, entry.wrapped_key, aad)
    except InvalidTag as exc:
        raise crypto.InvalidPassphraseError(
            "Passphrase did not unwrap this recipient entry."
        ) from exc


def unwrap_with_private_key(
    entry: WrappedRecipient,
    private_key: X25519PrivateKey,
    *,
    aad: bytes,
) -> bytes:
    if (
        entry.type != "pubkey"
        or entry.kind != "x25519"
        or entry.ephemeral_pubkey is None
        or entry.recipient_pubkey is None
    ):
        raise ValueError("entry is not an X25519 pubkey recipient")
    ephemeral_pub = keys.x25519_public_from_bytes(entry.ephemeral_pubkey)
    shared = private_key.exchange(ephemeral_pub)
    wrap_key = crypto.hkdf_derive_key(
        shared,
        info=HKDF_INFO_X25519 + b"|" + entry.ephemeral_pubkey + b"|" + entry.recipient_pubkey,
    )
    try:
        return AESGCM(wrap_key).decrypt(entry.wrap_nonce, entry.wrapped_key, aad)
    except InvalidTag as exc:
        raise crypto.InvalidPassphraseError(
            "Private key did not unwrap this recipient entry."
        ) from exc


def unwrap_content_key(
    entries: list[WrappedRecipient],
    *,
    aad: bytes,
    passphrase: str | None = None,
    private_key: X25519PrivateKey | None = None,
) -> bytes:
    """Try every recipient entry until one of them authenticates.

    The caller may supply a passphrase, a private key, or both. Pubkey
    recipients are tried in front of passphrase recipients because
    they are far cheaper to evaluate (Scrypt is intentionally slow).
    """
    if passphrase is None and private_key is None:
        raise ValueError("either passphrase or private_key must be provided")

    last_error: Exception | None = None

    if private_key is not None:
        for entry in entries:
            if entry.type == "pubkey" and entry.kind == "x25519":
                try:
                    return unwrap_with_private_key(entry, private_key, aad=aad)
                except (crypto.InvalidPassphraseError, ValueError) as exc:
                    last_error = exc

    if passphrase is not None:
        for entry in entries:
            if entry.type == "passphrase" and entry.kind == "scrypt":
                try:
                    return unwrap_with_passphrase(entry, passphrase, aad=aad)
                except (crypto.InvalidPassphraseError, ValueError) as exc:
                    last_error = exc

    raise crypto.InvalidPassphraseError(
        "No recipient entry could be unwrapped with the supplied credentials."
    ) from last_error


__all__ = [
    "HKDF_INFO_X25519",
    "PassphraseRecipient",
    "PublicKeyRecipient",
    "RecipientSpec",
    "WrappedRecipient",
    "wrap_for_passphrase",
    "wrap_for_pubkey",
    "wrap_for_recipients",
    "unwrap_with_passphrase",
    "unwrap_with_private_key",
    "unwrap_content_key",
]
