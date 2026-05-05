"""Tkinter GUI for SecureTrack v2.

The GUI keeps the same Encrypt / Decrypt entry points as the CLI but
exposes the new v2 affordances:

* multiple recipients (passphrase + one or more X25519 public keys);
* optional Ed25519 signing key;
* a progress bar that runs while encryption / decryption are happening
  on a worker thread;
* a status line that surfaces non-blocking errors.

The module is imported lazily so it never breaks ``pip install`` on
headless systems where ``tkinter`` is missing.
"""

from __future__ import annotations

import queue
import threading
from dataclasses import dataclass, field
from pathlib import Path

from . import crypto, keys, package, recipients

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
            "CLI (`python -m securetrack.cli`) instead. "
            f"Original import error: {_TK_IMPORT_ERROR}"
        )


# --- dataclasses describing pending operations -----------------------------


@dataclass
class EncryptRequest:
    input_path: Path
    output_path: Path
    passphrase: str | None
    recipient_pub_paths: list[Path] = field(default_factory=list)
    signing_key_path: Path | None = None
    signing_key_passphrase: str | None = None


@dataclass
class DecryptRequest:
    input_path: Path
    output_path: Path
    passphrase: str | None
    private_key_path: Path | None = None
    private_key_passphrase: str | None = None
    expected_signing_pubkey_path: Path | None = None


# --- worker --------------------------------------------------------------


def _do_encrypt(req: EncryptRequest) -> str:
    specs: list[recipients.RecipientSpec] = []
    for pub_path in req.recipient_pub_paths:
        pub = keys.load_x25519_public(pub_path)
        specs.append(recipients.PublicKeyRecipient(public_key=pub, label=pub_path.stem))
    if req.passphrase:
        specs.append(recipients.PassphraseRecipient(passphrase=req.passphrase))
    if not specs:
        raise ValueError(
            "Please supply at least one recipient: a passphrase or an X25519 public key."
        )

    signing_key = None
    if req.signing_key_path is not None:
        signing_key = keys.load_ed25519_private(
            req.signing_key_path, passphrase=req.signing_key_passphrase
        )

    metadata = package.encrypt_file(
        req.input_path,
        req.output_path,
        recipient_specs=specs,
        signing_key=signing_key,
    )
    return (
        f"Wrote {req.output_path.name}\n"
        f"Original size: {metadata.original_size_bytes:,} bytes\n"
        f"Chunks: {metadata.num_chunks}\n"
        f"SHA-256: {metadata.sha256_original[:16]}…"
    )


def _do_decrypt(req: DecryptRequest) -> str:
    private_key = None
    if req.private_key_path is not None:
        private_key = keys.load_x25519_private(
            req.private_key_path, passphrase=req.private_key_passphrase
        )
    expected_pub = None
    if req.expected_signing_pubkey_path is not None:
        expected_pub = keys.load_ed25519_public(req.expected_signing_pubkey_path)

    metadata = package.decrypt_file(
        req.input_path,
        req.output_path,
        passphrase=req.passphrase,
        private_key=private_key,
        expected_signing_pubkey=expected_pub,
    )
    return (
        f"Recovered {metadata.original_filename}\n"
        f"Size: {metadata.original_size_bytes:,} bytes\n"
        f"Chunks: {metadata.num_chunks}"
    )


# --- app builder ----------------------------------------------------------


def _make_app_class() -> type:
    _require_tk()
    tk = _tk
    filedialog = _filedialog
    messagebox = _messagebox
    ttk = _ttk

    class SecureTrackApp(tk.Tk):  # type: ignore[misc]
        """Tk window for SecureTrack v2."""

        def __init__(self) -> None:
            super().__init__()
            self.title("SecureTrack (prototype, v2)")
            self.geometry("640x460")
            self.minsize(560, 420)
            self._result_queue: queue.Queue[tuple[str, str]] = queue.Queue()
            self._build_layout()
            self.after(100, self._poll_results)

        # ---- layout ------------------------------------------------------

        def _build_layout(self) -> None:
            outer = ttk.Frame(self, padding=16)
            outer.pack(fill="both", expand=True)

            ttk.Label(
                outer,
                text="SecureTrack — encrypted audio sharing prototype",
                font=("TkDefaultFont", 11, "bold"),
            ).pack(anchor="w", pady=(0, 4))
            ttk.Label(
                outer,
                text=(
                    "v2: multiple recipients, optional Ed25519 signature, "
                    "chunked AEAD streaming."
                ),
                foreground="#666",
            ).pack(anchor="w", pady=(0, 12))

            tabs = ttk.Notebook(outer)
            tabs.pack(fill="both", expand=True)

            tabs.add(self._build_encrypt_tab(tabs), text="Encrypt")
            tabs.add(self._build_decrypt_tab(tabs), text="Decrypt")

            self.progress = ttk.Progressbar(outer, mode="indeterminate")
            self.progress.pack(fill="x", pady=(12, 4))
            self.status_var = tk.StringVar(value="Ready.")
            ttk.Label(outer, textvariable=self.status_var, foreground="#444").pack(
                anchor="w"
            )

        def _build_encrypt_tab(self, parent: object) -> object:
            frame = ttk.Frame(parent, padding=12)

            self.enc_input = tk.StringVar()
            self.enc_output = tk.StringVar()
            self.enc_passphrase = tk.StringVar()
            self.enc_recipients = tk.StringVar()  # newline-joined list
            self.enc_signing_key = tk.StringVar()
            self.enc_signing_passphrase = tk.StringVar()

            self._labelled_path(frame, 0, "Input WAV:", self.enc_input,
                                self._pick_open_wav)
            self._labelled_path(frame, 1, "Output package:", self.enc_output,
                                self._pick_save_package)

            ttk.Label(frame, text="Recipient passphrase (optional):").grid(
                row=2, column=0, sticky="w", pady=(8, 2)
            )
            ttk.Entry(frame, textvariable=self.enc_passphrase, show="*", width=40).grid(
                row=2, column=1, columnspan=2, sticky="we"
            )

            ttk.Label(frame, text="Recipient public keys (.pem):").grid(
                row=3, column=0, sticky="nw", pady=(8, 2)
            )
            recip_frame = ttk.Frame(frame)
            recip_frame.grid(row=3, column=1, columnspan=2, sticky="we")
            self.enc_recipient_listbox = tk.Listbox(recip_frame, height=4)
            self.enc_recipient_listbox.pack(side="left", fill="x", expand=True)
            recip_buttons = ttk.Frame(recip_frame)
            recip_buttons.pack(side="left", padx=(6, 0))
            ttk.Button(recip_buttons, text="Add…", command=self._add_recipient_pub).pack(
                fill="x"
            )
            ttk.Button(recip_buttons, text="Remove", command=self._remove_recipient_pub).pack(
                fill="x", pady=(4, 0)
            )

            self._labelled_path(
                frame, 4, "Signing key (.pem, optional):",
                self.enc_signing_key, self._pick_open_pem,
            )
            ttk.Label(frame, text="Signing key passphrase:").grid(
                row=5, column=0, sticky="w", pady=(8, 2)
            )
            ttk.Entry(frame, textvariable=self.enc_signing_passphrase, show="*", width=40).grid(
                row=5, column=1, columnspan=2, sticky="we"
            )

            ttk.Button(frame, text="Encrypt", command=self.on_encrypt).grid(
                row=6, column=0, columnspan=3, pady=(16, 0), sticky="we"
            )
            frame.columnconfigure(1, weight=1)
            return frame

        def _build_decrypt_tab(self, parent: object) -> object:
            frame = ttk.Frame(parent, padding=12)

            self.dec_input = tk.StringVar()
            self.dec_output = tk.StringVar()
            self.dec_passphrase = tk.StringVar()
            self.dec_private_key = tk.StringVar()
            self.dec_private_key_passphrase = tk.StringVar()
            self.dec_expect_signed_by = tk.StringVar()

            self._labelled_path(frame, 0, "Input package:", self.dec_input,
                                self._pick_open_package)
            self._labelled_path(frame, 1, "Output WAV:", self.dec_output,
                                self._pick_save_wav)

            ttk.Label(frame, text="Passphrase (optional):").grid(
                row=2, column=0, sticky="w", pady=(8, 2)
            )
            ttk.Entry(frame, textvariable=self.dec_passphrase, show="*", width=40).grid(
                row=2, column=1, columnspan=2, sticky="we"
            )

            self._labelled_path(
                frame, 3, "Private key (.pem):",
                self.dec_private_key, self._pick_open_pem,
            )
            ttk.Label(frame, text="Private key passphrase:").grid(
                row=4, column=0, sticky="w", pady=(8, 2)
            )
            ttk.Entry(
                frame, textvariable=self.dec_private_key_passphrase, show="*", width=40
            ).grid(row=4, column=1, columnspan=2, sticky="we")

            self._labelled_path(
                frame, 5, "Expect signed by (.pem, optional):",
                self.dec_expect_signed_by, self._pick_open_pem,
            )

            ttk.Button(frame, text="Decrypt", command=self.on_decrypt).grid(
                row=6, column=0, columnspan=3, pady=(16, 0), sticky="we"
            )
            frame.columnconfigure(1, weight=1)
            return frame

        def _labelled_path(
            self, parent: object, row: int, label: str, var: object, picker: object
        ) -> None:
            ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=(4, 2))
            ttk.Entry(parent, textvariable=var).grid(row=row, column=1, sticky="we")
            ttk.Button(parent, text="Browse…", command=picker).grid(
                row=row, column=2, padx=(6, 0)
            )

        # ---- pickers -----------------------------------------------------

        def _pick_open_wav(self) -> None:
            path = filedialog.askopenfilename(
                filetypes=[("WAV audio", "*.wav"), ("All files", "*.*")]
            )
            if path:
                self.enc_input.set(path)

        def _pick_save_package(self) -> None:
            path = filedialog.asksaveasfilename(
                defaultextension=".securetrack",
                filetypes=[("SecureTrack package", "*.securetrack")],
            )
            if path:
                self.enc_output.set(path)

        def _pick_open_package(self) -> None:
            path = filedialog.askopenfilename(
                filetypes=[
                    ("SecureTrack package", "*.securetrack"),
                    ("All files", "*.*"),
                ]
            )
            if path:
                self.dec_input.set(path)

        def _pick_save_wav(self) -> None:
            path = filedialog.asksaveasfilename(
                defaultextension=".wav", filetypes=[("WAV audio", "*.wav")]
            )
            if path:
                self.dec_output.set(path)

        def _pick_open_pem(self) -> None:
            path = filedialog.askopenfilename(
                filetypes=[("PEM key", "*.pem"), ("All files", "*.*")]
            )
            if not path:
                return
            # Try to populate whichever field has focus; fall back to
            # the encrypt signing key field.
            focused = self.focus_get()
            if focused is None:
                self.enc_signing_key.set(path)
            elif focused.winfo_name() in {"!entry5", "!entry6"}:
                self.enc_signing_key.set(path)
            else:
                # Decrypt tab fields are typically last to be focused.
                if not self.dec_private_key.get():
                    self.dec_private_key.set(path)
                else:
                    self.dec_expect_signed_by.set(path)

        def _add_recipient_pub(self) -> None:
            path = filedialog.askopenfilename(
                filetypes=[("PEM public key", "*.pem"), ("All files", "*.*")]
            )
            if path:
                self.enc_recipient_listbox.insert(tk.END, path)

        def _remove_recipient_pub(self) -> None:
            sel = self.enc_recipient_listbox.curselection()
            for idx in reversed(sel):
                self.enc_recipient_listbox.delete(idx)

        # ---- actions -----------------------------------------------------

        def on_encrypt(self) -> None:
            if not self.enc_input.get() or not self.enc_output.get():
                messagebox.showerror(
                    "Missing fields", "Please select an input WAV and an output package path."
                )
                return
            recipients_pubs = [
                Path(self.enc_recipient_listbox.get(i))
                for i in range(self.enc_recipient_listbox.size())
            ]
            req = EncryptRequest(
                input_path=Path(self.enc_input.get()),
                output_path=Path(self.enc_output.get()),
                passphrase=self.enc_passphrase.get() or None,
                recipient_pub_paths=recipients_pubs,
                signing_key_path=Path(self.enc_signing_key.get())
                if self.enc_signing_key.get()
                else None,
                signing_key_passphrase=self.enc_signing_passphrase.get() or None,
            )
            self._run_in_background("encrypt", req)

        def on_decrypt(self) -> None:
            if not self.dec_input.get() or not self.dec_output.get():
                messagebox.showerror(
                    "Missing fields", "Please select an input package and an output WAV path."
                )
                return
            req = DecryptRequest(
                input_path=Path(self.dec_input.get()),
                output_path=Path(self.dec_output.get()),
                passphrase=self.dec_passphrase.get() or None,
                private_key_path=Path(self.dec_private_key.get())
                if self.dec_private_key.get()
                else None,
                private_key_passphrase=self.dec_private_key_passphrase.get() or None,
                expected_signing_pubkey_path=Path(self.dec_expect_signed_by.get())
                if self.dec_expect_signed_by.get()
                else None,
            )
            self._run_in_background("decrypt", req)

        # ---- worker plumbing --------------------------------------------

        def _run_in_background(self, kind: str, req: object) -> None:
            self.progress.start(50)
            self.status_var.set(f"{kind.capitalize()}ing… (this may take a few seconds)")

            def worker() -> None:
                try:
                    if kind == "encrypt":
                        msg = _do_encrypt(req)  # type: ignore[arg-type]
                    elif kind == "decrypt":
                        msg = _do_decrypt(req)  # type: ignore[arg-type]
                    else:  # pragma: no cover
                        msg = "(no-op)"
                    self._result_queue.put((kind, msg))
                except (
                    crypto.InvalidPassphraseError,
                    crypto.InvalidSignatureError,
                    ValueError,
                    OSError,
                ) as exc:
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
                        self.status_var.set(f"{kind.split(':')[0].capitalize()} failed.")
                        messagebox.showerror(
                            f"{kind.split(':')[0].capitalize()} failed", msg
                        )
                    else:
                        self.status_var.set(f"{kind.capitalize()} succeeded.")
                        messagebox.showinfo(f"{kind.capitalize()} complete", msg)
            except queue.Empty:
                pass
            self.after(100, self._poll_results)

    return SecureTrackApp


def main() -> None:
    """Entry point for ``python -m securetrack.gui``."""
    app_cls = _make_app_class()
    app_cls().mainloop()


if __name__ == "__main__":
    main()
