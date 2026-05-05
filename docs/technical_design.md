# Technical Design (v2)

This document is an extended companion to Chapter 4 of the
dissertation. It describes the cryptographic choices, the v2
``.securetrack`` package format and the module layout of the
prototype.

## 1. Goals and non-goals

**Goals.**
* End-to-end confidentiality, integrity and origin authentication of
  an audio file shared between collaborators.
* No reliance on a shared passphrase: a sender can address a package
  to one or more X25519 public keys.
* No upper bound on file size that fits on disk: the audio is
  encrypted in fixed-size AEAD chunks rather than as a single blob.
* Reproducible measurements for the dissertation evaluation chapter.
* A code base small enough for a single student to explain in the
  viva.

**Non-goals (this version).**
* Cloud upload, key servers or directory services.
* Forward secrecy after long-term private-key compromise.
* Streaming I/O off disk (chunks are still materialised in memory;
  the chunk-on-disk variant is on the backlog).
* Defence against compromise of the sender or recipient endpoint.

## 2. Cryptographic design

| Concern               | Choice                  | Rationale                                                |
|-----------------------|-------------------------|----------------------------------------------------------|
| Symmetric primitive   | **AES-256-GCM**         | Authenticated encryption in a single primitive; widely audited; in `cryptography.hazmat.primitives.ciphers.aead`. |
| Content key           | 32 random bytes         | Drawn from `os.urandom`; one per package; never reused.  |
| Chunk size            | 1 MiB (default)         | Trade-off between per-chunk overhead (~16 B tag) and memory. |
| Per-chunk nonce       | 8 random bytes prefix `\|\|` 4-byte BE counter | Guarantees uniqueness within a package without storing 12 bytes per chunk. |
| Per-chunk AAD         | metadata bytes `\|\|` u32(index) `\|\|` u32(num_chunks) | Binds chunk position; chunks cannot be reordered, dropped or replayed. |
| Passphrase recipient KDF | **Scrypt** (n=2¹⁵, r=8, p=1, len=32) | Memory-hard; OWASP-recommended for password-derived keys. |
| Pubkey recipient ECDH | **X25519** (`exchange`) | Standard, fast, constant-time; raw 32-byte keys.        |
| Pubkey recipient KDF | **HKDF-SHA256**         | Bind the wrapping key to ``info = "securetrack-x25519-wrap-v2" \|\| ephemeral_pub \|\| recipient_pub`` so the same shared secret cannot be reused outside this protocol. |
| Wrap nonce / wrap tag | 12-byte AES-GCM nonce, 16-byte tag | Standard GCM. AAD = canonical metadata bytes. |
| Signature             | **Ed25519**             | Deterministic, fast, small public key, well-supported. |
| Signed message        | metadata `\|\|` SHA-256(recipients.json) `\|\|` SHA-256(ciphertext) | Binds the *whole* package to the signature without circular dependencies. |

### 2.1 Per-recipient wrapping in detail

```
content_key = random 32 bytes

# passphrase recipient
salt        = random 16 bytes
wrap_key    = Scrypt(passphrase, salt, n=2^15, r=8, p=1, len=32)
wrap_nonce  = random 12 bytes
wrapped     = AES-GCM-Encrypt(wrap_key, wrap_nonce, content_key, AAD=metadata)

# X25519 pubkey recipient
ephemeral_priv, ephemeral_pub = X25519.generate()
shared      = X25519(ephemeral_priv, recipient_pub)              # 32 bytes
info        = b"securetrack-x25519-wrap-v2" || ephemeral_pub || recipient_pub
wrap_key    = HKDF-SHA256(shared, info=info, length=32)
wrap_nonce  = random 12 bytes
wrapped     = AES-GCM-Encrypt(wrap_key, wrap_nonce, content_key, AAD=metadata)
```

The recipient unwraps by reversing the appropriate path: derive the
same Scrypt key (passphrase) or recompute the X25519 shared secret
(pubkey), then AES-GCM-Decrypt the wrapped content key.

### 2.2 Why AES-GCM and not ChaCha20-Poly1305?

GCM was chosen because (a) it is the format students encounter in
standard cryptography modules at Surrey, (b) it is hardware
accelerated on every machine the dissertation will run on, and (c) the
nonce/key handling is straightforward in this setting (per-chunk
nonce reuse is impossible because the prefix is fresh per package).
ChaCha20-Poly1305 is a perfectly good alternative and could be swapped
in by changing one import.

### 2.3 Why X25519 + HKDF + AES-GCM and not age?

`age` (the modern CLI tool) implements essentially the same
construction as we use here. We re-implemented it directly for two
reasons: (1) we can author the dissertation chapter end-to-end without
hand-waving, and (2) we keep a single dependency (`cryptography`)
rather than pulling in an opinionated CLI tool.

## 3. Package format `.securetrack` v2

A v2 package is a ZIP archive (`ZIP_STORED`, no compression) with
three required members and one optional member:

| Member                  | Required | Description                                       |
|-------------------------|----------|---------------------------------------------------|
| `metadata.json`         | yes      | UTF-8 JSON; also AES-GCM AAD for every chunk and every recipient wrap. |
| `recipients.json`       | yes      | List of wrapped content-key entries.              |
| `encrypted_audio.bin`   | yes      | Concatenated AES-256-GCM chunks (`ct_i \|\| tag_i`). |
| `signature.bin`         | optional | Ed25519 signature when the sender provided a signing key. |

### 3.1 Metadata schema

```json
{
  "format_version":      2,
  "algorithm":           "AES-256-GCM",
  "kdf":                 "scrypt",
  "kdf_params":          {"n": 32768, "r": 8, "p": 1, "length": 32},
  "chunk_size":          1048576,
  "num_chunks":          5,
  "nonce_prefix":        "<base64 8 bytes>",
  "original_filename":   "sample.wav",
  "original_size_bytes": 4194304,
  "sha256_original":     "<hex 64>",
  "created_utc":         "2026-05-04T22:47:12Z",
  "tool_version":        "0.2.0",
  "labels":              {"project": "demo"},
  "creator":             {"name": "alice"},
  "signature_algorithm": "Ed25519",
  "signing_pubkey":      "<base64 32 bytes>"
}
```

`signature_algorithm` and `signing_pubkey` are present only when the
package was signed.

The metadata is serialised with
`json.dumps(..., sort_keys=True, separators=(",", ":"))` so that the
bytes used as AAD are deterministic across implementations.

> **Why no `ciphertext_sha256` in the metadata?**
> If the ciphertext digest were part of the metadata, and the
> metadata is the AAD for every chunk, then any change to the digest
> would change the GCM tags and therefore the ciphertext, creating a
> non-converging fixed-point loop. The signature already binds the
> ciphertext digest in its signed message, so we don't need to store
> it.

### 3.2 Recipients schema

```json
{
  "recipients": [
    {
      "type":        "passphrase",
      "kind":        "scrypt",
      "salt":        "<base64 16>",
      "wrap_nonce":  "<base64 12>",
      "wrapped_key": "<base64 48>",
      "label":       "fallback"
    },
    {
      "type":             "pubkey",
      "kind":             "x25519",
      "recipient_pubkey": "<base64 32>",
      "ephemeral_pubkey": "<base64 32>",
      "wrap_nonce":       "<base64 12>",
      "wrapped_key":      "<base64 48>",
      "label":            "bob"
    }
  ]
}
```

Decryption tries pubkey entries first (cheap) and falls back to
passphrase entries (slow because of Scrypt).

### 3.3 Ciphertext layout

```
encrypted_audio.bin =
    chunk_0_ciphertext || chunk_0_tag    (chunk_size + 16 bytes)
    chunk_1_ciphertext || chunk_1_tag    (chunk_size + 16 bytes)
    ...
    chunk_{n-1}_ciphertext || chunk_{n-1}_tag   (last chunk may be shorter)
```

For chunk `i`:

```
nonce_i = nonce_prefix (8 B) || u32_be(i)        # 12 B AES-GCM nonce
aad_i   = metadata_bytes || u32_be(i) || u32_be(num_chunks)
ct_i    = AES-256-GCM-Encrypt(content_key, nonce_i, plaintext_i, aad_i)
```

A reader knows `chunk_size`, `num_chunks` and `original_size_bytes`
from the metadata, so it can deterministically split
`encrypted_audio.bin` into per-chunk ciphertext slices.

### 3.4 Signature

```
sig_msg   = metadata_bytes || b"|" || SHA-256(recipients.json) || b"|" || SHA-256(ciphertext)
signature = Ed25519-Sign(signing_priv, sig_msg)
```

`signing_pubkey` is recorded in the metadata. Verification re-computes
`sig_msg` from the freshly read members and checks the signature
against the recorded (or out-of-band-supplied) public key.

### 3.5 Expected overhead

| Component                | Approx. size |
|--------------------------|--------------|
| ZIP central directory    | ~250 B (3–4 members) |
| `metadata.json`          | ~600–900 B   |
| `recipients.json`        | ~250 B per recipient |
| AES-GCM tag per chunk    | 16 B (× num_chunks) |
| `signature.bin`          | 64 B (only when signed) |

For a 5 MiB WAV with one passphrase recipient, no signature, default
chunk size: about 1.1 KB overhead total (~0.02 %).

## 4. Module map

```
crypto.py          AES-GCM (one-shot + chunked), Scrypt, HKDF, Ed25519
keys.py            X25519 / Ed25519 keypair generation + PEM I/O
recipients.py      wrap/unwrap content key for passphrase / X25519
package.py         v2 format read/write, ties everything together
metrics.py         pure size / throughput helpers
benchmark.py       glue: timing + tamper test + CSV row
cli.py             argparse front-end (keygen / encrypt / decrypt / inspect / benchmark)
gui.py             Tkinter GUI (progress bar, recipient list, signing fields)
audacity_bridge.py mod-script-pipe driver + secure_export_from_audacity
```

The dependency graph is strictly downward: `crypto` knows nothing
about packages; `keys` knows nothing about recipients;
`recipients` and `package` use both of the above; `cli`, `gui` and
`audacity_bridge` are user-facing. Each layer can be tested in
isolation.

## 5. Threat model (informal)

**In scope.**
* A passive eavesdropper on the transport channel reading the
  contents of a `.securetrack` file.
* An adversary tampering with bytes of the file in transit (flipping
  bits, replacing the ciphertext, modifying the metadata or the
  recipients list, swapping or dropping individual chunks).
* A storage provider holding the file at rest who tries to read it.
* A recipient trying to brute-force a passphrase recipient offline
  (mitigated by Scrypt cost; ultimately bounded by passphrase
  entropy).
* An impersonation attack where a third party sends a forged
  `.securetrack` file pretending to come from the sender (mitigated
  by Ed25519 signatures and the `--expect-signed-by` flag).

**Out of scope.**
* Compromise of the sender or recipient endpoint while plaintext is
  in memory.
* Side-channel attacks on the local machine.
* Coercion or social engineering of the passphrase / private key.
* Recipients re-sharing the decrypted WAV after they have legitimately
  unwrapped it.
* Forward secrecy with respect to long-term X25519 private-key
  compromise (every old package addressed to that key remains
  decryptable).

## 6. Backlog of next steps

1. Cloud relay with at-rest re-encryption and revocable share links.
2. Project-level key management (one X25519 keypair per project, with
   a membership file the sender consults at encrypt time).
3. Header-only download + streaming decrypt so playback can start
   before the whole package is fetched.
4. Native Audacity menu integration via a Nyquist plug-in that calls
   the Python bridge in a daemon process.
5. Independent security review of the v2 format.
