# Demo Checklist

A short, ordered checklist for the live demo with the project
coordinator. Aim for ~5–7 minutes end-to-end.

## Before the demo

- [ ] Pull the latest commit on the demo branch.
- [ ] ``pip install -e ".[dev]"`` inside the activated ``.venv``.
- [ ] Open Audacity once, enable *mod-script-pipe* in
      *Edit ▸ Preferences ▸ Modules*, restart Audacity.
- [ ] Open a small project in Audacity (a generated tone or any
      short imported clip).
- [ ] Close any prior ``Documents/SecureTrack`` folder so you can
      show the *Create / Open SecureTrack Folders* step from a clean
      state.

## 1. Run the test suite (≈30 s)

```bat
python -m pytest -v
```

Expected: all tests pass. This is your first slide of evidence.

## 2. Open the SecureTrack app

```bat
run_securetrack.bat
```

Or:

```bat
python -m securetrack.gui
```

The window opens on the **Audacity Workflow** tab.

## 3. Create the workspace

- Click **Create / Open SecureTrack Folders**. The OS file
  manager opens at ``Documents\SecureTrack``.
- Briefly point at *Exports* and *Secure Packages*.

## 4. Start the watched folder

- In *Recipient ▸ Passphrase*, type ``demo passphrase``.
- Leave *Keep exported WAV* selected.
- Click **Start watching**. The status reads *Watching …*.

## 5. Export from Audacity

- Switch to Audacity.
- *File ▸ Export ▸ Export as WAV* into
  ``Documents\SecureTrack\Exports`` with a friendly name like
  ``demo.wav``.
- Switch back to SecureTrack.
- The activity log shows
  *Detected demo.wav. → Encrypting demo.wav… → Encrypted demo.wav -> demo.securetrack*.
- Open ``Documents\SecureTrack\Secure Packages`` and show the
  ``demo.securetrack`` file.

## 6. Decrypt the package

- Click the **Decrypt Package** tab.
- Pick ``demo.securetrack``.
- The output path autofills to ``demo_recovered.wav``.
- Type the passphrase ``demo passphrase``.
- Click **Open Secure Package**. A success dialog appears.

## 7. Import the recovered WAV into Audacity

- *File ▸ Import ▸ Audio…* → pick ``demo_recovered.wav``.
- Show the waveform on the Audacity timeline.

## 8. Show the benchmark CSV

```bat
python -m securetrack.cli benchmark ^
    -i examples\sample.wav ^
    -o results\benchmark_results.csv ^
    -p "demo passphrase"
```

Open ``results\benchmark_results.csv`` in Excel and point at
``hash_match`` and ``tamper_detection_passed`` (both ``true``).

## 9. (Optional) Audacity bridge

- Back on **Audacity Workflow** tab, click **Test connection** —
  status reads *Connected to Audacity.*
- ``python -m securetrack.cli audacity-test`` from a terminal
  shows the Help response.

## 10. Limitations

State briefly:

* Dissertation prototype, not a production-audited tool.
* Bridge-based plugin prototype, not a native C++ Audacity plug-in.
* Recipients must protect their passphrases.
* Secure deletion of exported WAVs is best-effort on modern
  filesystems.
* No cloud relay or revocation; the ``.securetrack`` package goes
  through whatever channel the user already trusts.
