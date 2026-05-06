# Audacity Macro Notes

This is an **optional** convenience for users who want a one-click
"export to the SecureTrack workspace" shortcut from inside Audacity
itself. The watched-folder workflow does not require this — Audacity's
plain *File ▸ Export ▸ Export as WAV* is enough — but a Macro saves
a few clicks if you encrypt every export.

The Macro import format has changed across Audacity versions, so the
manual steps below are written for Audacity 3.x and verified through
the *Tools ▸ Macros* editor that ships with Audacity rather than as
an importable file.

## 1. What the Macro does

Two steps: *Select All* the audio, then *Export* it as WAV into the
SecureTrack Exports folder.

```
SelectAll
Export2:  Filename="C:\Users\<you>\Documents\SecureTrack\Exports\track.wav"  NumChannels=2
```

You will adjust the path (``<you>``) and the channel count (``1`` for
mono, ``2`` for stereo) to match your project.

## 2. Manual steps in Audacity

1. In Audacity, open *Tools ▸ Macros…*.
2. Click *New* and name the macro something like
   **EncryptExport**.
3. With the macro selected, click *Insert* on the right side.
4. From the command list, choose **Select: All**.
5. Click *Insert* again and choose **Export 2…** (the entry is
   labelled *Export 2* and appears under *Export*).
6. In the parameter editor that pops up, set:
   * *Filename* — the full path to your SecureTrack Exports folder
     plus a filename, e.g.
     ``C:\Users\<you>\Documents\SecureTrack\Exports\track.wav``
   * *NumChannels* — ``2`` for stereo, ``1`` for mono.
7. Click *OK* on the parameter editor and *OK* on the Macros window.

## 3. Running the Macro

Two equivalent ways:

* *Tools ▸ Apply Macro… ▸ EncryptExport*
* If you bound it to a keyboard shortcut in
  *Edit ▸ Preferences ▸ Keyboard*, just press the shortcut.

The Macro overwrites the chosen WAV every time it runs. SecureTrack
treats a re-export with new contents as a new file (the size /
mtime change) and encrypts it again, so iterating on a track is
fine.

## 4. Recommended SecureTrack settings

When using a Macro that always exports to the same filename, the
*Keep exported WAV* file-handling option is the most ergonomic:
the Macro overwrites the WAV and SecureTrack re-encrypts on each
run.

If you would rather not keep plaintext exports around between
runs, use *Move exported WAV to the Archive folder* — the WAV is
removed from Exports after each successful encryption and the
Archive folder accumulates timestamped copies you can clean up
later.

## 5. Notes on portability

* The Macro path is hard-coded. On a different machine the path
  must be edited in *Tools ▸ Macros…* before the Macro will run.
* The Macro export format is unrelated to SecureTrack's package
  format. SecureTrack encrypts whichever WAV the Macro writes.
* If Audacity's *Export 2* dialog parameters change in a future
  version, the Macro entry may need to be recreated. Treat this
  document as guidance rather than as a binding script.
