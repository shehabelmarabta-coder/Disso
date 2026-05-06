"""SecureTrack desktop application.

Three tabs:

* **Audacity Workflow** — the main, recommended path. Sets up a local
  workspace under ``Documents/SecureTrack``, watches the *Exports*
  folder for new WAV files and encrypts them automatically. Also
  exposes the optional Audacity bridge for users with
  ``mod-script-pipe`` enabled.
* **Encrypt WAV** — encrypt a WAV that already lives somewhere on
  disk, in one shot.
* **Decrypt Package** — recover a WAV from a ``.securetrack`` package.

The GUI is aimed at non-technical users (e.g. musicians collaborating
on a track). All cryptographic detail lives in
``securetrack.crypto`` / ``securetrack.package`` / ``securetrack.recipients``;
this module just arranges file pickers, a passphrase entry, a
background worker and the watch-folder loop.
"""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

from . import audacity_bridge, crypto, keys, package, recipients, watch_folder

try:  # pragma: no cover - environment dependent
    import tkinter as _tk
    from tkinter import filedialog as _filedialog
    from tkinter import messagebox as _messagebox
    from tkinter import ttk as _ttk

    _TK_IMPORT_ERROR: ImportError | None = None
except ImportError as _exc:  # pragma: no cover
    _tk = None  # type: ignore[assignment]
    _filedialog = None  # type: ignore[assignment]
    _messagebox = None  # type: ignore[assignment]
    _ttk = None  # type: ignore[assignment]
    _TK_IMPORT_ERROR = _exc


def _require_tk() -> None:
    if _TK_IMPORT_ERROR is not None:  # pragma: no cover
        raise SystemExit(
            "tkinter is not available in this Python install; "
            "install your distribution's `python3-tk` package, or use the "
            "command-line interface (`python -m securetrack.cli`) instead. "
            f"Original import error: {_TK_IMPORT_ERROR}"
        )


# --- shared helpers --------------------------------------------------------


def _open_in_file_manager(path: Path) -> None:
    """Open ``path`` in the OS file manager (best effort)."""
    p = str(path)
    try:
        if sys.platform.startswith("win"):
            os.startfile(p)  # type: ignore[attr-defined]  # noqa: PTH123
        elif sys.platform == "darwin":
            subprocess.Popen(["open", p])
        else:
            subprocess.Popen(["xdg-open", p])
    except OSError:
        # If we cannot launch a file manager (headless container, etc.)
        # there is nothing to do; the calling tab still shows the path.
        pass


# --- worker request dataclasses -------------------------------------------


@dataclass
class _EncryptRequest:
    input_path: Path
    output_path: Path
    passphrase: str


@dataclass
class _DecryptRequest:
    input_path: Path
    output_path: Path
    passphrase: str | None
    private_key_path: Path | None = None


@dataclass
class _AudacityExportRequest:
    output_path: Path
    passphrase: str
    recipient_pub_path: Path | None = None


# --- worker bodies ---------------------------------------------------------


def _do_encrypt(req: _EncryptRequest) -> str:
    metadata = package.encrypt_file(
        req.input_path,
        req.output_path,
        recipient_specs=[recipients.PassphraseRecipient(passphrase=req.passphrase)],
    )
    return (
        f"Wrote {req.output_path.name}\n"
        f"Original size: {metadata.original_size_bytes:,} bytes\n"
        f"SHA-256: {metadata.sha256_original[:16]}…"
    )


def _do_decrypt(req: _DecryptRequest) -> str:
    private_key = None
    if req.private_key_path is not None:
        private_key = keys.load_x25519_private(req.private_key_path)
    metadata = package.decrypt_file(
        req.input_path,
        req.output_path,
        passphrase=req.passphrase,
        private_key=private_key,
    )
    return (
        f"Recovered {metadata.original_filename}\n"
        f"Saved to: {req.output_path}\n"
        f"Size: {metadata.original_size_bytes:,} bytes"
    )


def _do_audacity_export(req: _AudacityExportRequest) -> str:
    specs: list[recipients.RecipientSpec] = []
    if req.recipient_pub_path is not None:
        pub = keys.load_x25519_public(req.recipient_pub_path)
        specs.append(
            recipients.PublicKeyRecipient(public_key=pub, label=req.recipient_pub_path.stem)
        )
    if req.passphrase:
        specs.append(recipients.PassphraseRecipient(passphrase=req.passphrase))
    if not specs:
        raise ValueError(
            "Please supply a passphrase or a recipient public key in Advanced."
        )

    result = audacity_bridge.secure_export_from_audacity(
        req.output_path,
        recipient_specs=specs,
    )
    return (
        f"Exported audio from Audacity and encrypted it.\n"
        f"Saved to: {result}"
    )


# --- application factory --------------------------------------------------


def _make_app_class() -> type:
    _require_tk()
    tk = _tk
    filedialog = _filedialog
    messagebox = _messagebox
    ttk = _ttk

    class SecureTrackApp(tk.Tk):  # type: ignore[misc]
        """SecureTrack Tk application."""

        def __init__(self) -> None:
            super().__init__()
            self.title("SecureTrack")
            self.geometry("760x680")
            self.minsize(700, 620)

            self._result_queue: queue.Queue[tuple[str, object]] = queue.Queue()
            self._watcher: watch_folder.Watcher | None = None

            self._build_layout()
            self.after(100, self._poll_results)

        # ---- top-level layout -------------------------------------------

        def _build_layout(self) -> None:
            outer = ttk.Frame(self, padding=14)
            outer.pack(fill="both", expand=True)

            ttk.Label(
                outer, text="SecureTrack", font=("TkDefaultFont", 14, "bold"),
            ).pack(anchor="w")
            ttk.Label(
                outer,
                text="Secure encrypted audio sharing for Audacity",
                foreground="#555",
            ).pack(anchor="w", pady=(0, 10))

            tabs = ttk.Notebook(outer)
            tabs.pack(fill="both", expand=True)
            tabs.add(self._build_workflow_tab(tabs), text="Audacity Workflow")
            tabs.add(self._build_encrypt_tab(tabs), text="Encrypt WAV")
            tabs.add(self._build_decrypt_tab(tabs), text="Decrypt Package")

            self.progress = ttk.Progressbar(outer, mode="indeterminate")
            self.progress.pack(fill="x", pady=(10, 4))
            self.status_var = tk.StringVar(value="Ready.")
            ttk.Label(outer, textvariable=self.status_var, foreground="#444").pack(
                anchor="w"
            )

        # ---- tab 1: Audacity Workflow -----------------------------------

        def _build_workflow_tab(self, parent: object) -> object:
            frame = ttk.Frame(parent, padding=12)

            intro = (
                "SecureTrack helps protect unreleased audio before sharing.\n"
                "Work in Audacity as normal, export locally, and SecureTrack "
                "creates an encrypted package for collaborators.\n\n"
                "Steps:\n"
                "  1. Open your project in Audacity.\n"
                "  2. Export your WAV file to the Exports folder.\n"
                "  3. SecureTrack encrypts it locally.\n"
                "  4. The secure package is saved in the Secure Packages folder.\n"
                "  5. Send the .securetrack package to your collaborator.\n"
                "  6. They decrypt it into a WAV and import it into Audacity."
            )
            ttk.Label(frame, text=intro, justify="left").pack(anchor="w", pady=(0, 10))

            # Workspace section
            ws_box = ttk.LabelFrame(frame, text="Workspace", padding=10)
            ws_box.pack(fill="x", pady=(0, 8))
            ws_box.columnconfigure(1, weight=1)

            self.ws_root = tk.StringVar(value=str(watch_folder.default_workspace_root()))

            ttk.Label(ws_box, text="Folder root:").grid(row=0, column=0, sticky="w")
            ttk.Entry(ws_box, textvariable=self.ws_root).grid(
                row=0, column=1, sticky="we", padx=(6, 6)
            )
            ttk.Button(ws_box, text="Browse…", command=self._pick_ws_root).grid(
                row=0, column=2
            )
            buttons = ttk.Frame(ws_box)
            buttons.grid(row=1, column=0, columnspan=3, sticky="we", pady=(8, 0))
            ttk.Button(
                buttons, text="Create / Open SecureTrack Folders",
                command=self._create_or_open_workspace,
            ).pack(side="left")
            ttk.Button(
                buttons, text="Open Exports Folder",
                command=lambda: self._open_workspace_dir("exports"),
            ).pack(side="left", padx=(8, 0))
            ttk.Button(
                buttons, text="Open Secure Packages Folder",
                command=lambda: self._open_workspace_dir("packages"),
            ).pack(side="left", padx=(8, 0))

            # Recipient section
            rec_box = ttk.LabelFrame(frame, text="Recipient", padding=10)
            rec_box.pack(fill="x", pady=(0, 8))
            rec_box.columnconfigure(1, weight=1)

            self.wf_passphrase = tk.StringVar()
            self.wf_recipient_pub = tk.StringVar()

            ttk.Label(rec_box, text="Passphrase:").grid(row=0, column=0, sticky="w")
            ttk.Entry(rec_box, textvariable=self.wf_passphrase, show="*").grid(
                row=0, column=1, columnspan=2, sticky="we", padx=(6, 0)
            )

            adv = ttk.LabelFrame(rec_box, text="Advanced (optional)", padding=8)
            adv.grid(row=1, column=0, columnspan=3, sticky="we", pady=(8, 0))
            adv.columnconfigure(1, weight=1)
            ttk.Label(adv, text="Recipient public key (.pem):").grid(
                row=0, column=0, sticky="w"
            )
            ttk.Entry(adv, textvariable=self.wf_recipient_pub).grid(
                row=0, column=1, sticky="we", padx=(6, 6)
            )
            ttk.Button(
                adv, text="Browse…",
                command=lambda: self._pick_open_pem(self.wf_recipient_pub),
            ).grid(row=0, column=2)

            # File handling
            fh_box = ttk.LabelFrame(frame, text="After encryption", padding=10)
            fh_box.pack(fill="x", pady=(0, 8))
            self.wf_file_handling = tk.StringVar(value="keep")
            for value, label in (
                ("keep", "Keep exported WAV (recommended)"),
                ("move", "Move exported WAV to the Archive folder"),
                ("delete", "Delete exported WAV"),
            ):
                ttk.Radiobutton(
                    fh_box, text=label, value=value,
                    variable=self.wf_file_handling,
                ).pack(anchor="w")

            # Two action options
            actions = ttk.Frame(frame)
            actions.pack(fill="x", pady=(2, 0))
            actions.columnconfigure(0, weight=1, uniform="actions")
            actions.columnconfigure(1, weight=1, uniform="actions")

            opt_a = ttk.LabelFrame(
                actions, text="Option A — Watch Exports folder (recommended)",
                padding=10,
            )
            opt_a.grid(row=0, column=0, sticky="nswe", padx=(0, 6))
            ttk.Label(
                opt_a,
                text=(
                    "Export from Audacity to the Exports folder. SecureTrack "
                    "encrypts each new WAV automatically."
                ),
                wraplength=320, justify="left", foreground="#555",
            ).pack(anchor="w", pady=(0, 6))
            self.watch_status = tk.StringVar(value="Not watching.")
            ttk.Label(opt_a, textvariable=self.watch_status, foreground="#444").pack(
                anchor="w", pady=(0, 6)
            )
            row_a = ttk.Frame(opt_a)
            row_a.pack(fill="x")
            ttk.Button(
                row_a, text="Start Watching Export Folder",
                command=self._start_watching,
            ).pack(side="left")
            ttk.Button(
                row_a, text="Stop Watching",
                command=self._stop_watching,
            ).pack(side="left", padx=(6, 0))

            opt_b = ttk.LabelFrame(
                actions, text="Option B — Export directly from Audacity",
                padding=10,
            )
            opt_b.grid(row=0, column=1, sticky="nswe", padx=(6, 0))
            ttk.Label(
                opt_b,
                text=(
                    "Drive Audacity over mod-script-pipe to render the active "
                    "project to a temporary WAV and encrypt it."
                ),
                wraplength=320, justify="left", foreground="#555",
            ).pack(anchor="w", pady=(0, 6))
            self.bridge_status = tk.StringVar(value="Connection not tested yet.")
            ttk.Label(opt_b, textvariable=self.bridge_status, foreground="#444").pack(
                anchor="w", pady=(0, 6)
            )
            row_b = ttk.Frame(opt_b)
            row_b.pack(fill="x")
            ttk.Button(
                row_b, text="Test Audacity Connection",
                command=self.on_test_audacity,
            ).pack(side="left")
            ttk.Button(
                row_b, text="Export from Audacity and Encrypt",
                command=self.on_audacity_export,
            ).pack(side="left", padx=(6, 0))

            # Activity log
            log_box = ttk.LabelFrame(frame, text="Activity log", padding=8)
            log_box.pack(fill="both", expand=True, pady=(10, 0))
            self.activity_log = tk.Text(
                log_box, height=8, wrap="word", state="disabled",
                background="#fafafa",
            )
            self.activity_log.pack(fill="both", expand=True)

            return frame

        # ---- tab 2: Encrypt --------------------------------------------

        def _build_encrypt_tab(self, parent: object) -> object:
            frame = ttk.Frame(parent, padding=14)

            self.enc_input = tk.StringVar()
            self.enc_output = tk.StringVar()
            self.enc_passphrase = tk.StringVar()

            ttk.Label(
                frame,
                text=(
                    "Encrypt a WAV file that already lives somewhere on your "
                    "computer. The Audacity Workflow tab is usually the easier "
                    "path."
                ),
                wraplength=620, justify="left", foreground="#555",
            ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

            self._labelled_path(
                frame, 1, "Input WAV file:", self.enc_input,
                lambda: self._pick_open_wav(self.enc_input, after=self._suggest_enc_output),
            )
            self._labelled_path(
                frame, 2, "Save secure package to:", self.enc_output,
                lambda: self._pick_save_package(self.enc_output),
            )
            self._labelled_password(
                frame, 3, "Recipient passphrase:", self.enc_passphrase
            )

            ttk.Button(frame, text="Encrypt", command=self.on_encrypt).grid(
                row=4, column=0, columnspan=3, pady=(18, 0), sticky="we"
            )
            ttk.Label(
                frame,
                text=(
                    "Choose a passphrase of at least 12 characters and share "
                    "it with the recipient through a different channel."
                ),
                foreground="#666", wraplength=620, justify="left",
            ).grid(row=5, column=0, columnspan=3, sticky="w", pady=(12, 0))
            frame.columnconfigure(1, weight=1)
            return frame

        # ---- tab 3: Decrypt --------------------------------------------

        def _build_decrypt_tab(self, parent: object) -> object:
            frame = ttk.Frame(parent, padding=14)

            self.dec_input = tk.StringVar()
            self.dec_output = tk.StringVar()
            self.dec_passphrase = tk.StringVar()
            self.dec_private_key = tk.StringVar()

            self._labelled_path(
                frame, 0, "Input secure package:", self.dec_input,
                lambda: self._pick_open_package(self.dec_input, after=self._suggest_dec_output),
            )
            self._labelled_path(
                frame, 1, "Save recovered WAV to:", self.dec_output,
                lambda: self._pick_save_wav(self.dec_output),
            )
            self._labelled_password(
                frame, 2, "Passphrase:", self.dec_passphrase
            )

            adv = ttk.LabelFrame(frame, text="Advanced (optional)", padding=10)
            adv.grid(row=3, column=0, columnspan=3, sticky="we", pady=(14, 0))
            adv.columnconfigure(1, weight=1)
            ttk.Label(adv, text="Private key (.pem):").grid(row=0, column=0, sticky="w")
            ttk.Entry(adv, textvariable=self.dec_private_key).grid(
                row=0, column=1, sticky="we", padx=(6, 6)
            )
            ttk.Button(
                adv, text="Browse…",
                command=lambda: self._pick_open_pem(self.dec_private_key),
            ).grid(row=0, column=2)

            ttk.Button(frame, text="Decrypt", command=self.on_decrypt).grid(
                row=4, column=0, columnspan=3, pady=(18, 0), sticky="we"
            )
            frame.columnconfigure(1, weight=1)
            return frame

        # ---- shared widget helpers -------------------------------------

        def _labelled_path(
            self, parent: object, row: int, label: str, var: object, picker: object
        ) -> None:
            ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=(4, 2))
            ttk.Entry(parent, textvariable=var).grid(
                row=row, column=1, sticky="we", padx=(6, 6)
            )
            ttk.Button(parent, text="Browse…", command=picker).grid(row=row, column=2)

        def _labelled_password(
            self, parent: object, row: int, label: str, var: object
        ) -> None:
            ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=(8, 2))
            ttk.Entry(parent, textvariable=var, show="*").grid(
                row=row, column=1, columnspan=2, sticky="we", padx=(6, 0)
            )

        # ---- pickers ---------------------------------------------------

        def _pick_open_wav(self, var, after=None) -> None:
            path = filedialog.askopenfilename(
                title="Choose a WAV file",
                filetypes=[("WAV audio", "*.wav"), ("All files", "*.*")],
            )
            if path:
                var.set(path)
                if after:
                    after()

        def _pick_save_package(self, var) -> None:
            path = filedialog.asksaveasfilename(
                title="Save secure package as…",
                defaultextension=".securetrack",
                filetypes=[("SecureTrack package", "*.securetrack")],
            )
            if path:
                var.set(path)

        def _pick_open_package(self, var, after=None) -> None:
            path = filedialog.askopenfilename(
                title="Choose a .securetrack package",
                filetypes=[
                    ("SecureTrack package", "*.securetrack"),
                    ("All files", "*.*"),
                ],
            )
            if path:
                var.set(path)
                if after:
                    after()

        def _pick_save_wav(self, var) -> None:
            path = filedialog.asksaveasfilename(
                title="Save recovered WAV as…",
                defaultextension=".wav",
                filetypes=[("WAV audio", "*.wav")],
            )
            if path:
                var.set(path)

        def _pick_open_pem(self, var) -> None:
            path = filedialog.askopenfilename(
                title="Choose a key file",
                filetypes=[("PEM key", "*.pem"), ("All files", "*.*")],
            )
            if path:
                var.set(path)

        def _pick_ws_root(self) -> None:
            path = filedialog.askdirectory(title="Choose a folder for the SecureTrack workspace")
            if path:
                self.ws_root.set(path)

        # ---- default-output suggestions --------------------------------

        def _suggest_enc_output(self) -> None:
            if self.enc_input.get() and not self.enc_output.get():
                p = Path(self.enc_input.get())
                self.enc_output.set(str(p.with_suffix(".securetrack")))

        def _suggest_dec_output(self) -> None:
            if self.dec_input.get() and not self.dec_output.get():
                p = Path(self.dec_input.get())
                self.dec_output.set(str(p.with_name(p.stem + "_recovered.wav")))

        # ---- workspace actions -----------------------------------------

        def _current_workspace(self) -> watch_folder.WorkspacePaths:
            return watch_folder.WorkspacePaths.from_root(Path(self.ws_root.get()))

        def _create_or_open_workspace(self) -> None:
            ws = watch_folder.ensure_workspace(self._current_workspace())
            self._log(f"Workspace ready at {ws.root}")
            _open_in_file_manager(ws.root)

        def _open_workspace_dir(self, which: str) -> None:
            ws = watch_folder.ensure_workspace(self._current_workspace())
            target = {"exports": ws.exports_dir, "packages": ws.packages_dir}[which]
            _open_in_file_manager(target)

        # ---- watcher actions -------------------------------------------

        def _build_recipient_specs(self) -> list[recipients.RecipientSpec]:
            specs: list[recipients.RecipientSpec] = []
            if self.wf_recipient_pub.get():
                pub = keys.load_x25519_public(Path(self.wf_recipient_pub.get()))
                specs.append(
                    recipients.PublicKeyRecipient(
                        public_key=pub,
                        label=Path(self.wf_recipient_pub.get()).stem,
                    )
                )
            if self.wf_passphrase.get():
                specs.append(
                    recipients.PassphraseRecipient(passphrase=self.wf_passphrase.get())
                )
            return specs

        def _start_watching(self) -> None:
            if self._watcher is not None and self._watcher.is_running:
                return
            try:
                specs = self._build_recipient_specs()
            except (ValueError, OSError) as exc:
                messagebox.showerror("Recipient error", str(exc))
                return
            if not specs:
                messagebox.showerror(
                    "Need a recipient",
                    "Please enter a passphrase, or pick a recipient public key in Advanced.",
                )
                return

            ws = watch_folder.ensure_workspace(self._current_workspace())
            self._watcher = watch_folder.Watcher(
                ws,
                recipient_specs=specs,
                file_handling=self.wf_file_handling.get(),  # type: ignore[arg-type]
            )

            def callback(event: watch_folder.WatchEvent) -> None:
                self._result_queue.put(("watch-event", event))

            self._watcher.start(callback)
            self.watch_status.set(f"Watching {ws.exports_dir}.")
            self._log(f"Started watching {ws.exports_dir}")

        def _stop_watching(self) -> None:
            if self._watcher is None or not self._watcher.is_running:
                self.watch_status.set("Not watching.")
                return

            def stopper() -> None:
                self._watcher.stop()  # type: ignore[union-attr]
                self._result_queue.put(("watch-stopped", None))

            threading.Thread(target=stopper, daemon=True).start()

        # ---- bridge actions --------------------------------------------

        def on_test_audacity(self) -> None:
            self.bridge_status.set("Checking…")
            self.update_idletasks()
            try:
                paths = audacity_bridge.detect_pipe_paths()
                if not audacity_bridge.is_audacity_pipe_available(paths):
                    self.bridge_status.set("Audacity not detected.")
                    messagebox.showwarning(
                        "Audacity not detected",
                        "Open Audacity, enable mod-script-pipe "
                        "(Edit ▸ Preferences ▸ Modules), restart Audacity, "
                        "and open an audio project.",
                    )
                    return
                with audacity_bridge.AudacityScriptPipe.connect(timeout_seconds=3.0) as p:
                    p.ping()
                self.bridge_status.set("Connected to Audacity.")
                self._log("Audacity connection succeeded.")
            except audacity_bridge.AudacityPipeError as exc:
                self.bridge_status.set("Connection failed.")
                messagebox.showerror("Audacity connection failed", str(exc))

        def on_audacity_export(self) -> None:
            ws = watch_folder.ensure_workspace(self._current_workspace())
            default_name = ws.packages_dir / "audacity_export.securetrack"
            output_path = filedialog.asksaveasfilename(
                title="Save secure package as…",
                initialdir=str(ws.packages_dir),
                initialfile=default_name.name,
                defaultextension=".securetrack",
                filetypes=[("SecureTrack package", "*.securetrack")],
            )
            if not output_path:
                return
            if not self.wf_passphrase.get() and not self.wf_recipient_pub.get():
                messagebox.showerror(
                    "Need a recipient",
                    "Please enter a passphrase, or pick a recipient public key in Advanced.",
                )
                return
            req = _AudacityExportRequest(
                output_path=Path(output_path),
                passphrase=self.wf_passphrase.get(),
                recipient_pub_path=(
                    Path(self.wf_recipient_pub.get())
                    if self.wf_recipient_pub.get()
                    else None
                ),
            )
            self._run_in_background("audacity-export", req)

        # ---- one-shot Encrypt / Decrypt buttons ------------------------

        def on_encrypt(self) -> None:
            if not self.enc_input.get() or not self.enc_output.get():
                messagebox.showerror(
                    "Missing fields",
                    "Please choose an input WAV file and an output package path.",
                )
                return
            if not self.enc_passphrase.get():
                messagebox.showerror(
                    "Passphrase required",
                    "Please enter a recipient passphrase.",
                )
                return
            req = _EncryptRequest(
                input_path=Path(self.enc_input.get()),
                output_path=Path(self.enc_output.get()),
                passphrase=self.enc_passphrase.get(),
            )
            self._run_in_background("encrypt", req)

        def on_decrypt(self) -> None:
            if not self.dec_input.get() or not self.dec_output.get():
                messagebox.showerror(
                    "Missing fields",
                    "Please choose an input package and an output WAV path.",
                )
                return
            passphrase = self.dec_passphrase.get() or None
            private_key_path = (
                Path(self.dec_private_key.get())
                if self.dec_private_key.get()
                else None
            )
            if passphrase is None and private_key_path is None:
                messagebox.showerror(
                    "Need credentials",
                    "Enter the passphrase, or pick a private key in Advanced.",
                )
                return
            req = _DecryptRequest(
                input_path=Path(self.dec_input.get()),
                output_path=Path(self.dec_output.get()),
                passphrase=passphrase,
                private_key_path=private_key_path,
            )
            self._run_in_background("decrypt", req)

        # ---- background plumbing ---------------------------------------

        def _run_in_background(self, kind: str, req: object) -> None:
            self.progress.start(50)
            self.status_var.set(self._working_label(kind))

            def worker() -> None:
                try:
                    if kind == "encrypt":
                        msg = _do_encrypt(req)  # type: ignore[arg-type]
                    elif kind == "decrypt":
                        msg = _do_decrypt(req)  # type: ignore[arg-type]
                    elif kind == "audacity-export":
                        msg = _do_audacity_export(req)  # type: ignore[arg-type]
                    else:  # pragma: no cover
                        msg = "(no-op)"
                    self._result_queue.put((kind, msg))
                except crypto.InvalidPassphraseError as exc:
                    self._result_queue.put((kind + ":error", str(exc)))
                except crypto.InvalidSignatureError as exc:
                    self._result_queue.put((kind + ":error", str(exc)))
                except audacity_bridge.AudacityPipeError as exc:
                    self._result_queue.put((kind + ":error", str(exc)))
                except (ValueError, OSError) as exc:
                    self._result_queue.put((kind + ":error", str(exc)))
                except Exception as exc:  # noqa: BLE001
                    self._result_queue.put((kind + ":error", repr(exc)))

            threading.Thread(target=worker, daemon=True).start()

        def _poll_results(self) -> None:
            try:
                while True:
                    kind, payload = self._result_queue.get_nowait()
                    if kind == "watch-event":
                        self._handle_watch_event(payload)  # type: ignore[arg-type]
                        continue
                    if kind == "watch-stopped":
                        self.watch_status.set("Not watching.")
                        self._log("Watcher stopped.")
                        continue
                    self.progress.stop()
                    if kind.endswith(":error"):
                        op = kind.split(":")[0]
                        self.status_var.set(self._failure_label(op))
                        messagebox.showerror(self._failure_title(op), str(payload))
                    else:
                        self.status_var.set(self._success_label(kind))
                        messagebox.showinfo(self._success_title(kind), str(payload))
            except queue.Empty:
                pass
            self.after(100, self._poll_results)

        # ---- watcher event handling ------------------------------------

        def _handle_watch_event(self, event: watch_folder.WatchEvent) -> None:
            line = event.message or event.kind
            self._log(line)
            if event.kind in ("encrypting", "detected"):
                self.watch_status.set("Encrypting a new WAV…")
            elif event.kind == "encrypted":
                self.watch_status.set("Last package: " + (event.target.name if event.target else ""))
            elif event.kind == "started":
                self.watch_status.set(event.message or "Watching.")
            elif event.kind == "stopped":
                self.watch_status.set("Not watching.")

        def _log(self, line: str) -> None:
            self.activity_log.config(state="normal")
            self.activity_log.insert("end", line + "\n")
            self.activity_log.see("end")
            self.activity_log.config(state="disabled")

        # ---- labels -----------------------------------------------------

        @staticmethod
        def _working_label(kind: str) -> str:
            if kind == "encrypt":
                return "Encrypting… please wait."
            if kind == "decrypt":
                return "Decrypting… please wait."
            if kind == "audacity-export":
                return "Exporting from Audacity and encrypting… please wait."
            return "Working…"

        @staticmethod
        def _success_label(kind: str) -> str:
            return {
                "encrypt": "Encryption complete.",
                "decrypt": "Decryption complete.",
                "audacity-export": "Audacity export and encryption complete.",
            }.get(kind, "Done.")

        @staticmethod
        def _success_title(kind: str) -> str:
            return {
                "encrypt": "Encryption complete",
                "decrypt": "Decryption complete",
                "audacity-export": "Audacity export complete",
            }.get(kind, "Done")

        @staticmethod
        def _failure_label(op: str) -> str:
            return {
                "encrypt": "Encryption failed.",
                "decrypt": "Decryption failed.",
                "audacity-export": "Audacity export failed.",
            }.get(op, "Failed.")

        @staticmethod
        def _failure_title(op: str) -> str:
            return {
                "encrypt": "Encryption failed",
                "decrypt": "Decryption failed",
                "audacity-export": "Audacity export failed",
            }.get(op, "Failed")

        # ---- shutdown --------------------------------------------------

        def destroy(self) -> None:  # type: ignore[override]
            try:
                if self._watcher is not None and self._watcher.is_running:
                    self._watcher.stop(timeout=1.0)
            finally:
                super().destroy()

    return SecureTrackApp


def main() -> None:
    """Entry point for ``python -m securetrack.gui``."""
    app_cls = _make_app_class()
    app_cls().mainloop()


if __name__ == "__main__":
    main()


__all__ = ["main"]
