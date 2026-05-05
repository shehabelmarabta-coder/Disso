"""SecureTrack desktop application.

A simple Tk-based front end with three tabs:

* **Encrypt WAV** — turn an exported WAV into a ``.securetrack`` package.
* **Decrypt Package** — recover the WAV from a ``.securetrack`` package.
* **Audacity Export** — connect to Audacity, export the current project
  and encrypt it in one step.

The GUI is intentionally aimed at non-technical users (e.g. musicians
collaborating on a track). All cryptographic detail lives in
``securetrack.crypto`` and ``securetrack.package``; this module just
arranges file pickers, a passphrase entry and a worker thread.
"""

from __future__ import annotations

import queue
import threading
from dataclasses import dataclass, field
from pathlib import Path

from . import audacity_bridge, crypto, keys, package, recipients

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


# --- worker bodies (synchronous; called from a background thread) ---------


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
            self.geometry("680x500")
            self.minsize(620, 480)
            self._result_queue: queue.Queue[tuple[str, str]] = queue.Queue()
            self._build_layout()
            self.after(100, self._poll_results)

        # ---- layout -----------------------------------------------------

        def _build_layout(self) -> None:
            outer = ttk.Frame(self, padding=16)
            outer.pack(fill="both", expand=True)

            ttk.Label(
                outer,
                text="SecureTrack",
                font=("TkDefaultFont", 14, "bold"),
            ).pack(anchor="w")
            ttk.Label(
                outer,
                text="Secure encrypted audio sharing for Audacity",
                foreground="#555",
            ).pack(anchor="w", pady=(0, 12))

            tabs = ttk.Notebook(outer)
            tabs.pack(fill="both", expand=True)

            tabs.add(self._build_encrypt_tab(tabs), text="Encrypt WAV")
            tabs.add(self._build_decrypt_tab(tabs), text="Decrypt Package")
            tabs.add(self._build_audacity_tab(tabs), text="Audacity Export")

            self.progress = ttk.Progressbar(outer, mode="indeterminate")
            self.progress.pack(fill="x", pady=(12, 4))
            self.status_var = tk.StringVar(value="Ready.")
            ttk.Label(outer, textvariable=self.status_var, foreground="#444").pack(
                anchor="w"
            )

        # ---- tab 1: Encrypt --------------------------------------------

        def _build_encrypt_tab(self, parent: object) -> object:
            frame = ttk.Frame(parent, padding=14)

            self.enc_input = tk.StringVar()
            self.enc_output = tk.StringVar()
            self.enc_passphrase = tk.StringVar()

            self._labelled_path(
                frame, 0, "Input WAV file:", self.enc_input,
                lambda: self._pick_open_wav(self.enc_input, after=self._suggest_enc_output),
            )
            self._labelled_path(
                frame, 1, "Save secure package to:", self.enc_output,
                lambda: self._pick_save_package(self.enc_output),
            )
            self._labelled_password(
                frame, 2, "Recipient passphrase:", self.enc_passphrase
            )

            ttk.Button(frame, text="Encrypt", command=self.on_encrypt).grid(
                row=3, column=0, columnspan=3, pady=(18, 0), sticky="we"
            )
            ttk.Label(
                frame,
                text=(
                    "Tip: choose a passphrase of at least 12 characters "
                    "and share it with the recipient through a different channel."
                ),
                foreground="#666",
                wraplength=600,
                justify="left",
            ).grid(row=4, column=0, columnspan=3, sticky="w", pady=(12, 0))
            frame.columnconfigure(1, weight=1)
            return frame

        # ---- tab 2: Decrypt --------------------------------------------

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

        # ---- tab 3: Audacity Export ------------------------------------

        def _build_audacity_tab(self, parent: object) -> object:
            frame = ttk.Frame(parent, padding=14)

            self.aud_output = tk.StringVar()
            self.aud_passphrase = tk.StringVar()
            self.aud_recipient_pub = tk.StringVar()
            self.aud_status = tk.StringVar(value="Connection not tested yet.")

            ttk.Label(frame, text="Step 1 — Test that Audacity is reachable:").grid(
                row=0, column=0, columnspan=3, sticky="w"
            )
            row1 = ttk.Frame(frame)
            row1.grid(row=1, column=0, columnspan=3, sticky="we", pady=(4, 8))
            ttk.Button(
                row1, text="Test Audacity Connection",
                command=self.on_test_audacity,
            ).pack(side="left")
            ttk.Label(
                row1, textvariable=self.aud_status,
                foreground="#444", padding=(10, 0, 0, 0),
            ).pack(side="left")

            ttk.Separator(frame).grid(row=2, column=0, columnspan=3, sticky="we", pady=8)

            ttk.Label(frame, text="Step 2 — Export and encrypt:").grid(
                row=3, column=0, columnspan=3, sticky="w", pady=(0, 6)
            )
            self._labelled_path(
                frame, 4, "Save secure package to:", self.aud_output,
                lambda: self._pick_save_package(self.aud_output),
            )
            self._labelled_password(
                frame, 5, "Recipient passphrase:", self.aud_passphrase
            )

            adv = ttk.LabelFrame(frame, text="Advanced (optional)", padding=10)
            adv.grid(row=6, column=0, columnspan=3, sticky="we", pady=(10, 0))
            adv.columnconfigure(1, weight=1)
            ttk.Label(adv, text="Recipient public key (.pem):").grid(
                row=0, column=0, sticky="w"
            )
            ttk.Entry(adv, textvariable=self.aud_recipient_pub).grid(
                row=0, column=1, sticky="we", padx=(6, 6)
            )
            ttk.Button(
                adv, text="Browse…",
                command=lambda: self._pick_open_pem(self.aud_recipient_pub),
            ).grid(row=0, column=2)

            ttk.Button(
                frame, text="Export from Audacity and Encrypt",
                command=self.on_audacity_export,
            ).grid(row=7, column=0, columnspan=3, pady=(18, 0), sticky="we")

            ttk.Label(
                frame,
                text=(
                    "If the connection test fails: open Audacity, enable "
                    "mod-script-pipe (Edit ▸ Preferences ▸ Modules), restart "
                    "Audacity, and open an audio project."
                ),
                foreground="#666",
                wraplength=600,
                justify="left",
            ).grid(row=8, column=0, columnspan=3, sticky="w", pady=(12, 0))

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

        # ---- default-output suggestions --------------------------------

        def _suggest_enc_output(self) -> None:
            if self.enc_input.get() and not self.enc_output.get():
                p = Path(self.enc_input.get())
                self.enc_output.set(str(p.with_suffix(".securetrack")))

        def _suggest_dec_output(self) -> None:
            if self.dec_input.get() and not self.dec_output.get():
                p = Path(self.dec_input.get())
                self.dec_output.set(str(p.with_name(p.stem + "_recovered.wav")))

        # ---- actions ---------------------------------------------------

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

        def on_test_audacity(self) -> None:
            self.aud_status.set("Checking…")
            self.update_idletasks()
            try:
                paths = audacity_bridge.detect_pipe_paths()
                if not audacity_bridge.is_audacity_pipe_available(paths):
                    self.aud_status.set("Audacity not detected.")
                    messagebox.showwarning(
                        "Audacity not detected",
                        "Open Audacity, enable mod-script-pipe "
                        "(Edit ▸ Preferences ▸ Modules), restart Audacity, "
                        "and open an audio project.",
                    )
                    return
                with audacity_bridge.AudacityScriptPipe.connect(timeout_seconds=3.0) as p:
                    p.ping()
                self.aud_status.set("Connected to Audacity.")
            except audacity_bridge.AudacityPipeError as exc:
                self.aud_status.set("Connection failed.")
                messagebox.showerror("Audacity connection failed", str(exc))

        def on_audacity_export(self) -> None:
            if not self.aud_output.get():
                messagebox.showerror(
                    "Missing fields", "Please choose where to save the secure package."
                )
                return
            if not self.aud_passphrase.get() and not self.aud_recipient_pub.get():
                messagebox.showerror(
                    "Need a recipient",
                    "Please enter a passphrase, or pick a recipient public key in Advanced.",
                )
                return
            req = _AudacityExportRequest(
                output_path=Path(self.aud_output.get()),
                passphrase=self.aud_passphrase.get(),
                recipient_pub_path=(
                    Path(self.aud_recipient_pub.get())
                    if self.aud_recipient_pub.get()
                    else None
                ),
            )
            self._run_in_background("audacity-export", req)

        # ---- worker plumbing -------------------------------------------

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
                    kind, msg = self._result_queue.get_nowait()
                    self.progress.stop()
                    if kind.endswith(":error"):
                        op = kind.split(":")[0]
                        self.status_var.set(self._failure_label(op))
                        messagebox.showerror(self._failure_title(op), msg)
                    else:
                        self.status_var.set(self._success_label(kind))
                        messagebox.showinfo(self._success_title(kind), msg)
            except queue.Empty:
                pass
            self.after(100, self._poll_results)

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

    return SecureTrackApp


def main() -> None:
    """Entry point for ``python -m securetrack.gui``."""
    app_cls = _make_app_class()
    app_cls().mainloop()


if __name__ == "__main__":
    main()


# Re-export public names so ``from securetrack.gui import main`` works
# without pulling tk in.
__all__ = ["main"]


# Use the *_ field default factories so ``ruff`` does not flag the
# dataclasses as unused. (They are used inside the worker functions.)
_ = field
