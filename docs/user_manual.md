# SecureTrack User Manual (v2 prototype)

This is the short user-facing guide for the dissertation prototype.
For dissertation context see ``README.md`` and ``technical_design.md``.

## 1. Audience

You have just received a ``.securetrack`` file from a collaborator,
or you would like to send one. SecureTrack is a small command line
and GUI tool that wraps a WAV file in a recipient-targeted package
and unwraps it again on the other side. v2 supports two recipient
modes:

* **Passphrase**: the sender and recipient share a passphrase out of
  band (e.g. via a phone call). Simple but requires a side channel.
* **X25519 public key**: the recipient publishes a public key once;
  the sender encrypts to that key with no shared secret. Recommended.

A package may also be **signed** by the sender with an Ed25519 key,
so a recipient can verify it really came from them.

## 2. Installation

```bash
git clone <this repository>
cd secure-audacity-track-sharing
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

python -m securetrack.cli --version
```

## 3. Generating keypairs (one-time setup)

You only need to do this the first time you use the tool.

```bash
# Long-term X25519 keypair for receiving encrypted files
python -m securetrack.cli keygen --kind x25519 \
    --private-out ~/.securetrack/me.priv.pem \
    --public-out  ~/.securetrack/me.pub.pem \
    --encrypt-private        # prompts for a passphrase to protect the file at rest

# (Optional) Ed25519 signing keypair if you want recipients to verify
# that packages came from you.
python -m securetrack.cli keygen --kind ed25519 \
    --private-out ~/.securetrack/me.sign.pem \
    --public-out  ~/.securetrack/me.verify.pem \
    --encrypt-private
```

Send the **`*.pub.pem`** and **`*.verify.pem`** files to your
collaborators. Keep the **`*.priv.pem`** and **`*.sign.pem`** files
private.

## 4. Sending a WAV to a collaborator (sender side)

1. Export your project from Audacity:
   *File ▸ Export ▸ Export as WAV* into any folder you like.
2. Encrypt the file. Two common modes:

   **Public-key mode (recommended).** Bob already gave you `bob.pub.pem`:

   ```bash
   python -m securetrack.cli encrypt \
       -i exported.wav -o for-bob.securetrack \
       --recipient bob.pub.pem \
       --signing-key ~/.securetrack/me.sign.pem \
       --label project=demo --creator-name alice
   ```

   **Passphrase mode (no shared key infrastructure).**

   ```bash
   python -m securetrack.cli encrypt \
       -i exported.wav -o share.securetrack \
       --passphrase "12-character-or-longer-secret"
   ```

3. Send the ``.securetrack`` file to your collaborator using whatever
   transport you trust (Dropbox, WeTransfer, email…). The contents
   are encrypted, so the storage provider cannot read them.

## 5. Receiving a `.securetrack` package (recipient side)

1. Save the file you received to disk.
2. Decrypt it. Match the mode the sender used:

   **Public-key mode:**

   ```bash
   python -m securetrack.cli decrypt \
       -i for-bob.securetrack -o recovered.wav \
       --key ~/.securetrack/me.priv.pem \
       --expect-signed-by alice.verify.pem        # optional but recommended
   ```

   **Passphrase mode:**

   ```bash
   python -m securetrack.cli decrypt \
       -i share.securetrack -o recovered.wav \
       --passphrase "..."
   ```

3. Open ``recovered.wav`` in Audacity (*File ▸ Open*) as you normally
   would.

If the passphrase is wrong, the wrong private key is supplied, the
package has been tampered with, or the signature does not verify
under ``--expect-signed-by``, decryption fails with a clear error and
no plaintext is written.

| Exit code | Meaning                                            |
|-----------|----------------------------------------------------|
| 0         | Success                                            |
| 2         | Bad arguments (file missing, etc.)                 |
| 3         | Cannot unwrap the content key (wrong passphrase or wrong private key) |
| 4         | Malformed package                                  |
| 5         | Signature did not verify                           |

## 6. Inspecting a package without decrypting

```bash
python -m securetrack.cli inspect -i share.securetrack --json
```

Prints the canonical metadata JSON: format version, original
filename and size, SHA-256 of the original, creator, labels and
(when signed) the signing public key. Recipient list and ciphertext
remain encrypted.

## 7. Using the GUI

```bash
python -m securetrack.gui
```

A two-tab Tkinter window:

* **Encrypt** — pick the input WAV, the output package path, an
  optional passphrase, zero or more recipient public keys (Add /
  Remove), and an optional Ed25519 signing key. A progress bar runs
  while Scrypt is working.
* **Decrypt** — pick the input package, the output WAV, and either
  a passphrase or a private key. Optionally enforce a specific
  signing public key.

## 8. Using SecureTrack with Audacity directly

If Audacity is running with the *mod-script-pipe* module enabled
(*Edit ▸ Preferences ▸ Modules ▸ mod-script-pipe ▸ Enabled*), the
bridge can drive an `Export2` directly without you having to use the
File menu:

```python
from pathlib import Path
from securetrack.audacity_bridge import secure_export_from_audacity
from securetrack.recipients import PassphraseRecipient

secure_export_from_audacity(
    Path("share.securetrack"),
    recipient_specs=[PassphraseRecipient("test password")],
)
```

The temporary plaintext WAV is overwritten with zeros and unlinked
before the function returns, even on errors.

## 9. Frequently asked questions

**Can I lose my private key / passphrase?**
Yes. There is no recovery mechanism by design — that would defeat
end-to-end encryption. Back up `*.priv.pem` and store passphrases in
a password manager.

**Can the recipient share the decrypted file further?**
Yes. Once decrypted, the WAV is an ordinary file. SecureTrack
protects the file *in transit and at rest*, not after a recipient
chooses to redistribute it.

**Why is the first encryption noticeably slower than the second one?**
Scrypt key derivation runs once per *passphrase recipient*. Pubkey
recipients use X25519 + HKDF, which take microseconds. If you only
add pubkey recipients, encryption is essentially as fast as raw
AES-GCM.

**Where are the benchmark numbers?**
See ``results/benchmark_results.csv`` after running the
``benchmark`` command, or ``docs/evaluation_plan.md`` for the
methodology.
