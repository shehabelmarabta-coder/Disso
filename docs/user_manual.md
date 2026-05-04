# SecureTrack User Manual (Prototype)

This is the short user-facing guide for the dissertation prototype.
For dissertation context see ``README.md`` and ``technical_design.md``.

## 1. Audience

You have just received a ``.securetrack`` file from a collaborator, or
you would like to send one. SecureTrack is a small command line and
GUI tool that wraps a WAV file in a passphrase-protected package and
unwraps it again on the other side.

## 2. Installation

```bash
git clone <this repository>
cd secure-audacity-track-sharing
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

You can confirm the install with:

```bash
python -m securetrack.cli --version
```

## 3. Sending a WAV (sender side)

1. Export your project from Audacity:
   *File → Export → Export as WAV* into any folder you like.
2. Encrypt the file:

   ```bash
   python -m securetrack.cli encrypt \
       --input  /path/to/exported.wav \
       --output /path/to/share.securetrack
   ```

   You will be prompted for a passphrase. Choose one of at least 12
   characters and **share it with the recipient through a different
   channel** (for example a phone call), never alongside the file.
3. Send the ``.securetrack`` file to your collaborator using whatever
   transport you already trust (Dropbox, WeTransfer, email…). The
   contents are encrypted, so the storage provider cannot read them.

## 4. Receiving a `.securetrack` package (recipient side)

1. Save the file you received to disk.
2. Decrypt it:

   ```bash
   python -m securetrack.cli decrypt \
       --input  /path/to/share.securetrack \
       --output /path/to/recovered.wav
   ```

3. Open ``recovered.wav`` in Audacity (*File → Open*) as you normally
   would.

If the passphrase is wrong, or the file has been tampered with in
transit, decryption fails with a clear error message and exit code 3
or 4 — no audio is written.

## 5. Using the GUI

For users who prefer not to use a terminal:

```bash
python -m securetrack.gui
```

The window has two buttons:

* **Encrypt WAV…** — pick a WAV, choose where to save the package,
  enter a passphrase. The status bar reports success.
* **Decrypt package…** — pick a ``.securetrack`` file, choose where
  to save the recovered WAV, enter the agreed passphrase.

The GUI is a skeleton. Drag and drop, progress bars, recipient
management and a project view are planned for a later iteration.

## 6. Inspecting a package without decrypting

Every package contains a ``metadata.json`` member that is **not**
encrypted (only authenticated). You can read it with any zip tool:

```bash
unzip -p share.securetrack metadata.json
```

This shows the original filename, original size, SHA-256 hash and
creation timestamp, but not the audio itself.

## 7. Frequently asked questions

**Can I lose my passphrase?**
Yes. There is no recovery mechanism by design — that would defeat
end-to-end encryption. Save the passphrase in your password manager.

**Can the recipient share the decrypted file further?**
Yes. Once decrypted, the WAV is an ordinary file. SecureTrack
protects the file *in transit and at rest*, not after a recipient
chooses to redistribute it.

**Why is encryption a little slow on the first call?**
Scrypt is intentionally slow to make brute-force attacks expensive.
A round-trip on a 5 MB file is still well under a second on a
mid-range laptop.

**Where are the benchmark numbers?**
See ``results/benchmark_results.csv`` after running the
``benchmark`` command, or ``docs/evaluation_plan.md`` for the
methodology.
