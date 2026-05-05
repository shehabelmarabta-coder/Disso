# SecureTrack User Manual

A short guide for non-technical users. For dissertation context see
``../README.md`` and ``technical_design.md``.

## What SecureTrack does

SecureTrack lets you share an unreleased WAV file with a collaborator
without putting the audio in plaintext on a third-party service.
You enter a passphrase, the application produces a sealed
``.securetrack`` package, and your collaborator opens that package
on the other side.

The application has three tabs:

* **Encrypt WAV** — turn an existing WAV into a ``.securetrack`` package.
* **Decrypt Package** — recover the WAV from a ``.securetrack`` package.
* **Audacity Export** — export the audio that is currently open in
  Audacity and encrypt it in one step.

## 1. Opening SecureTrack

* On Windows, double-click ``run_securetrack.bat`` in the project
  folder.
* On macOS / Linux, or as a fallback on Windows, run:

  ```
  python -m securetrack.gui
  ```

The window opens with the three tabs above. The *Ready.* line at
the bottom turns into a progress message while the application is
working.

## 2. Encrypting a WAV file

Use this tab when you already have a WAV file you want to share.

1. Click **Browse…** next to *Input WAV file* and choose the file.
2. The *Save secure package to* field is filled in for you with a
   sensible default. Change it if you want to.
3. Type a passphrase next to *Recipient passphrase*. Make it at least
   12 characters and share it with your collaborator through a
   **different** channel — for example a phone call or a different
   messaging app — never in the same email as the file itself.
4. Click **Encrypt**.

When the operation finishes a dialog confirms it and lists the
output file, original size and SHA-256 fingerprint of the audio.

## 3. Decrypting a secure package

Use this tab when you receive a ``.securetrack`` file from someone
else.

1. Click **Browse…** next to *Input secure package* and choose the
   file.
2. The *Save recovered WAV to* field is filled in automatically.
3. Type the passphrase your collaborator sent you.
4. Click **Decrypt**.

If your collaborator used an X25519 public key instead of a
passphrase, open the *Advanced (optional)* section and pick your
private key file (``.pem``) there.

If the passphrase is wrong, or the package has been altered on the
way, the application reports the failure and does **not** write any
audio.

## 4. Connecting to Audacity

Audacity comes with a small scripting interface called
``mod-script-pipe``. SecureTrack uses it to ask Audacity for the
audio in the project that is currently open. The interface is
disabled by default — you only need to do this once.

### Enabling mod-script-pipe

1. Open Audacity.
2. Go to *Edit ▸ Preferences ▸ Modules*.
3. Find *mod-script-pipe* in the list and set it to **Enabled**.
4. Click **OK** and **restart Audacity**. (The setting only takes
   effect on restart.)
5. Open the project you want to share.

### Testing the connection

1. In SecureTrack, open the **Audacity Export** tab.
2. Click **Test Audacity Connection**. The label next to the button
   changes to *Connected to Audacity.* if everything is in order.

If it says *Audacity not detected* or *Connection failed*, see
*Common errors and fixes* below.

## 5. Exporting and encrypting from Audacity

After the connection test succeeds:

1. In the **Audacity Export** tab, choose where to save the
   ``.securetrack`` package.
2. Enter a passphrase. (Or use a recipient public key from
   *Advanced (optional)*.)
3. Click **Export from Audacity and Encrypt**.

SecureTrack asks Audacity to select all tracks, exports them to a
temporary WAV, encrypts that WAV into the secure package, and
deletes the temporary file before reporting success. You do **not**
need to press *Ctrl+A* or use *File ▸ Export* yourself.

## 6. Common errors and fixes

| What you see                                  | What it usually means                                                              | What to do                                                                                                                                       |
|-----------------------------------------------|------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| *Audacity not detected.*                      | Audacity is not running, or it has not been opened since you enabled the module.   | Open Audacity, enable *mod-script-pipe* in *Preferences ▸ Modules*, **restart Audacity**, then click *Test Audacity Connection* again.           |
| *Connection failed.* / pipe not found         | mod-script-pipe is disabled, or Audacity was started before it was enabled.        | Enable the module and **restart Audacity** so the pipes are created.                                                                             |
| *Audacity exported an empty or near-empty WAV.* | The Audacity project does not contain audio yet.                                  | Open or import an audio file in Audacity, make sure it appears in the timeline, then try **Export from Audacity and Encrypt** again.            |
| *Decryption failed: wrong passphrase or the package has been tampered with.* | Wrong passphrase, or the file changed in transit.                | Check the passphrase character-for-character. If you are sure it is correct, ask the sender to re-send the package — the file may be corrupted. |
| *No recipient entry could be unwrapped with the supplied credentials.* | A package addressed to a public key was opened with the wrong private key. | Pick the right private key file in *Advanced (optional)*.                                                                                      |
| *Cannot load private key* / *cannot load signing key* | The chosen ``.pem`` file is not a valid key file.                              | Pick a key generated by ``securetrack keygen``.                                                                                                  |
| *Package signature does not verify*           | The sender signed the package with a different signing key.                        | Confirm the public key file used for *Expect signed by* matches the sender's signing key.                                                        |

## 7. Tips

* **Pick strong passphrases.** A 12-character random passphrase is
  much stronger than a short clever phrase.
* **Send the passphrase out of band.** Don't put it in the same
  email or message as the package.
* **Keep your private key safe.** If you use the public-key option,
  back up your ``.pem`` file. There is no recovery if you lose it.
* **Don't share the recovered WAV.** SecureTrack protects the file
  while it is in transit and at rest. Once a recipient decrypts it,
  it is an ordinary WAV again.
