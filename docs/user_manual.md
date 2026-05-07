# SecureTrack User Manual

A short guide for non-technical users. For dissertation context see
``../README.md`` and ``technical_design.md``.

## What SecureTrack does

SecureTrack lets you share an unreleased WAV file with a collaborator
without putting the audio in plaintext on a third-party service.
You enter a passphrase, the application produces a sealed
``.securetrack`` package, and your collaborator opens that package
on the other side.

It integrates with Audacity at the export stage. You keep using
Audacity exactly as you do today — SecureTrack just steps in between
the export and the upload.

The application has three tabs:

* **Audacity Workflow** — the recommended path. Watches an export
  folder or drives Audacity directly.
* **Encrypt WAV** — turn an existing WAV into a ``.securetrack``
  package in one shot.
* **Decrypt Package** — recover the WAV from a ``.securetrack``
  package.

## 1. Opening SecureTrack

* On Windows, double-click ``run_securetrack.bat`` in the project
  folder.
* On macOS / Linux, or as a fallback on Windows, run:

  ```
  python -m securetrack.gui
  ```

## 2. The Audacity Workflow tab

This is the tab that opens first.

### Step 1 — Set up your local workspace

1. The *Folder root* defaults to ``Documents/SecureTrack``. Leave it
   alone, or click *Browse…* to pick somewhere else.
2. Click **Create / Open SecureTrack Folders**. SecureTrack creates:
   * ``Exports`` — where Audacity will write WAV files.
   * ``Secure Packages`` — where SecureTrack writes the
     ``.securetrack`` files.
   * ``Recovered WAVs`` — a sensible place to save decrypted files
     coming back the other way.
   * ``Archive`` — used only if you choose *Move exported WAV*.
3. The *Open Exports Folder* and *Open Secure Packages Folder*
   buttons launch the OS file manager so you can verify what is
   inside.

### Step 2 — Choose the recipient

* Type a passphrase next to *Passphrase*. Make it at least 12
  characters and share it with your collaborator through a
  **different** channel (e.g. a phone call, never the same email as
  the package).
* Optionally pick a recipient public key under
  *Advanced (optional)*. This is for users who already use
  ``securetrack keygen`` and prefer not to share a passphrase.

### Step 3 — Choose what to do with each exported WAV

Under *After encryption*:

* **Keep exported WAV** *(recommended)* — the WAV stays in the
  Exports folder. Safe choice.
* **Move exported WAV to the Archive folder** — the WAV is moved
  out of Exports to keep that folder tidy.
* **Delete exported WAV** — the WAV is overwritten with zeros and
  unlinked.

### Step 4 — Pick how SecureTrack should integrate with Audacity

You have two options. They use the same passphrase / recipient /
file-handling settings.

#### Option A — Watch Exports folder (recommended)

The simplest path:

1. Click **Start Watching Export Folder**. The status line shows
   *Watching …*.
2. Open Audacity and work as normal.
3. *File ▸ Export ▸ Export as WAV* into the **Exports** folder.
   SecureTrack detects the new file, encrypts it and writes the
   package to **Secure Packages**.
4. The activity log at the bottom of the tab shows each step
   (*Detected song.wav* → *Encrypting song.wav…* → *Encrypted
   song.wav -> song.securetrack*).
5. When you are done, click **Stop Watching**.

The watcher waits about two seconds after the WAV stops growing
before encrypting it, so it never reads a half-written file.

#### Option B — Export directly from Audacity

This option uses Audacity's built-in scripting interface.

1. Make sure mod-script-pipe is enabled (see *3. Connecting to
   Audacity* below).
2. Open the project you want to share in Audacity.
3. Click **Test Audacity Connection**. The status next to the
   button changes to *Connected to Audacity.* if everything is in
   order.
4. Click **Export from Audacity and Encrypt**, choose where to
   save the ``.securetrack`` package, and confirm.

SecureTrack asks Audacity to select all tracks, exports them to a
temporary WAV, encrypts that WAV into the package, and deletes the
temporary file before reporting success. You do not need to press
*Ctrl+A* or use *File ▸ Export* yourself.

## 3. Connecting to Audacity

Audacity comes with a small scripting interface called
``mod-script-pipe``. SecureTrack uses it for *Option B*. The
interface is disabled by default and you only need to do this once.

### Enabling mod-script-pipe

1. Open Audacity.
2. Go to *Edit ▸ Preferences ▸ Modules*.
3. Find *mod-script-pipe* in the list and set it to **Enabled**.
4. Click **OK** and **restart Audacity**. The setting only takes
   effect on restart.
5. Open the project you want to share.

### Testing the connection

In SecureTrack, click *Test Audacity Connection* on the Audacity
Workflow tab. If it says *Audacity not detected* or *Connection
failed*, see *Common errors and fixes* below.

## 4. Encrypting a WAV file by hand

Use the **Encrypt WAV** tab when you already have a WAV file
somewhere on disk and just want to encrypt it without setting up
the workflow folders:

1. Click **Browse…** next to *Input WAV file* and choose the file.
2. The output path is filled in for you. Change it if you want.
3. Type a passphrase.
4. Click **Encrypt**.

## 5. Decrypting a secure package

Use the **Decrypt Package** tab when you receive a ``.securetrack``
file from someone else:

1. Click **Browse…** next to *Input secure package* and choose the
   file.
2. The output path is filled in automatically.
3. Type the passphrase your collaborator sent you.
4. Click **Decrypt**.

If your collaborator used an X25519 public key instead of a
passphrase, open *Advanced (optional)* and pick your private key
file (``.pem``) there.

## 6. Common errors and fixes

| What you see                                  | What it usually means                                                              | What to do                                                                                                                             |
|-----------------------------------------------|------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| *Audacity not detected.*                      | Audacity is not running, or it has not been opened since you enabled the module.   | Open Audacity, enable *mod-script-pipe*, **restart Audacity**, then click *Test Audacity Connection* again.                            |
| *Connection failed.* / pipe not found         | mod-script-pipe is disabled, or Audacity was started before it was enabled.        | Enable the module and **restart Audacity** so the pipes are created.                                                                   |
| *Audacity exported an empty or near-empty WAV.* | The Audacity project does not contain audio yet.                                 | Open or import an audio file in Audacity and try **Export from Audacity and Encrypt** again.                                            |
| *Decryption failed: wrong passphrase or the package has been tampered with.* | Wrong passphrase, or the file changed in transit.                | Check the passphrase character-for-character. If you are sure it is correct, ask the sender to re-send the package.                    |
| *No recipient entry could be unwrapped with the supplied credentials.* | Package addressed to a public key was opened with the wrong private key.  | Pick the right private key file in *Advanced (optional)*.                                                                              |
| *Package signature does not verify*           | The sender signed the package with a different signing key.                        | Confirm the public key file used for *Expect signed by* matches the sender's signing key.                                              |
| Watcher status stays *Not watching.*          | You forgot to enter a passphrase or pick a public key.                              | Fill in the *Recipient* section, then click *Start Watching Export Folder*.                                                            |
| *Audacity is not open* / *project contains no audio* | Self-explanatory; the bridge has nothing to export.                          | Open Audacity, open or import audio, try again.                                                                                         |

## 7. Advanced: public / private key pairs

A passphrase is the recommended way to use SecureTrack and is enough
for most collaborations. If you would rather not share a passphrase,
the application also supports **public/private key** pairs:

* The **public key** is something you can share freely with
  collaborators. They use it to encrypt packages addressed to you.
* The **private key** stays on your machine and must remain secret.
  It is the only thing that can open packages addressed to your
  public key.

### Generating a key pair from the GUI

1. Open SecureTrack and switch to the **Decrypt Package** tab.
2. In the **Advanced (optional)** area click **Generate Key Pair…**.
3. The default save folder is ``Documents/SecureTrack/Keys`` and the
   default name is ``collaborator_key``. Change either if you want.
4. Click **Generate**. SecureTrack writes two files:
   * ``<name>_public.pem`` — share this with collaborators.
   * ``<name>_private.pem`` — keep this secret.
5. The success dialog offers:
   * **Copy public key path** — puts the public key file path on
     the clipboard so you can paste it into an email or message to
     a collaborator.
   * **Open Key Folder** — opens the folder in the OS file manager
     so you can see both files.

The application never displays the contents of the private key.

### Using a public key as a recipient

* In the **Audacity Workflow** tab the recipient public key goes
  under *Recipient ▸ Advanced (optional) ▸ Recipient public key
  (.pem)*.
* In the **Decrypt Package** tab you supply your *own* private key
  under *Advanced (optional) ▸ Private key (.pem)*.

You do not need to use both passphrase and key — pick one, or use
them together if you want a passphrase fallback in addition to the
public key.

## 8. Tips

* Pick strong passphrases. A 12-character random passphrase is much
  stronger than a short clever phrase.
* Send the passphrase out of band — never in the same email as the
  package.
* Keep your private key safe. There is no recovery if you lose it.
* Once a recipient decrypts a package, the audio is an ordinary
  WAV. SecureTrack protects the file *in transit and at rest*, not
  after a recipient chooses to redistribute it.

## 9. Audacity macros (optional)

If you want a one-key export-to-secure-folder shortcut from inside
Audacity itself, see ``audacity_macro_notes.md`` for the manual
steps to build a small Audacity Macro that exports the active
project straight into the Exports folder.
