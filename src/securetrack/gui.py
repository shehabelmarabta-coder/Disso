"""Minimal Tkinter GUI skeleton for SecureTrack.

This is intentionally a *skeleton*: it exposes Encrypt / Decrypt buttons
that delegate to the same library functions the CLI uses. The dissertation
plan is to flesh this out (drag-and-drop, progress bar, recipient picker,
error reporting) once the cryptographic core is stable.

Usage::

    python -m securetrack.gui

The GUI uses only the Python standard library (``tkinter``). Some Linux
distributions package ``tkinter`` separately as ``python3-tk``; if it is
not available, importing this module is fine but actually launching the
window will raise a clear :class:`SystemExit`.
"""

from __future__ import annotations

from pathlib import Path

from . import crypto, package

# Try to import tkinter at module load time, but tolerate its absence so
# that simply importing ``securetrack.gui`` never fails on a headless
# install. A missing tkinter is reported when ``main()`` is called.
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


def _make_app_class() -> type:
    """Return the :class:`SecureTrackApp` class, requiring tkinter to be present."""
    _require_tk()

    tk = _tk
    filedialog = _filedialog
    messagebox = _messagebox
    ttk = _ttk

    class SecureTrackApp(tk.Tk):  # type: ignore[misc, name-defined]
        """Tk application window with Encrypt and Decrypt actions."""

        def __init__(self) -> None:
            super().__init__()
            self.title("SecureTrack (prototype)")
            self.geometry("520x260")
            self.resizable(False, False)
            self._build_layout()

        def _build_layout(self) -> None:
            outer = ttk.Frame(self, padding=16)
            outer.pack(fill="both", expand=True)

            title = ttk.Label(
                outer,
                text="SecureTrack — encrypted audio sharing prototype",
                font=("TkDefaultFont", 11, "bold"),
            )
            title.pack(anchor="w", pady=(0, 8))

            info = ttk.Label(
                outer,
                text=(
                    "Choose a WAV file to encrypt, or a .securetrack package to decrypt.\n"
                    "You will be prompted for the passphrase and an output location."
                ),
                justify="left",
            )
            info.pack(anchor="w", pady=(0, 12))

            button_row = ttk.Frame(outer)
            button_row.pack(anchor="w")
            ttk.Button(button_row, text="Encrypt WAV…", command=self.on_encrypt).pack(
                side="left", padx=(0, 8)
            )
            ttk.Button(button_row, text="Decrypt package…", command=self.on_decrypt).pack(
                side="left"
            )

            self.status_var = tk.StringVar(value="Ready.")
            ttk.Label(outer, textvariable=self.status_var, foreground="#444").pack(
                anchor="w", pady=(16, 0)
            )

        def _ask_passphrase(self, title: str) -> str | None:
            dialog = tk.Toplevel(self)
            dialog.title(title)
            dialog.transient(self)
            dialog.grab_set()
            ttk.Label(dialog, text="Passphrase:").pack(padx=12, pady=(12, 4))
            var = tk.StringVar()
            entry = ttk.Entry(dialog, textvariable=var, show="*", width=32)
            entry.pack(padx=12, pady=4)
            entry.focus_set()
            result: dict[str, str | None] = {"value": None}

            def submit() -> None:
                result["value"] = var.get()
                dialog.destroy()

            ttk.Button(dialog, text="OK", command=submit).pack(pady=(8, 12))
            dialog.bind("<Return>", lambda _e: submit())
            self.wait_window(dialog)
            return result["value"] or None

        def on_encrypt(self) -> None:
            in_path = filedialog.askopenfilename(
                title="Select WAV to encrypt",
                filetypes=[("WAV audio", "*.wav"), ("All files", "*.*")],
            )
            if not in_path:
                return
            out_path = filedialog.asksaveasfilename(
                title="Save encrypted package as…",
                defaultextension=".securetrack",
                filetypes=[("SecureTrack package", "*.securetrack")],
            )
            if not out_path:
                return
            passphrase = self._ask_passphrase("Encrypt — choose a passphrase")
            if not passphrase:
                return

            try:
                metadata = package.encrypt_file(
                    Path(in_path), Path(out_path), passphrase
                )
            except Exception as exc:  # noqa: BLE001 - surface any error in the dialog
                messagebox.showerror("Encryption failed", str(exc))
                return
            self.status_var.set(
                f"Encrypted {Path(in_path).name} -> {Path(out_path).name}"
            )
            messagebox.showinfo(
                "Encryption complete",
                f"Wrote {Path(out_path).name}\n"
                f"Original size: {metadata.original_size_bytes} bytes\n"
                f"SHA-256: {metadata.sha256_original[:16]}…",
            )

        def on_decrypt(self) -> None:
            in_path = filedialog.askopenfilename(
                title="Select .securetrack package",
                filetypes=[
                    ("SecureTrack package", "*.securetrack"),
                    ("All files", "*.*"),
                ],
            )
            if not in_path:
                return
            out_path = filedialog.asksaveasfilename(
                title="Save recovered audio as…",
                defaultextension=".wav",
                filetypes=[("WAV audio", "*.wav")],
            )
            if not out_path:
                return
            passphrase = self._ask_passphrase("Decrypt — enter the passphrase")
            if not passphrase:
                return

            try:
                metadata = package.decrypt_file(
                    Path(in_path), Path(out_path), passphrase
                )
            except crypto.InvalidPassphraseError as exc:
                messagebox.showerror("Decryption failed", str(exc))
                return
            except Exception as exc:  # noqa: BLE001
                messagebox.showerror("Could not read package", str(exc))
                return
            self.status_var.set(
                f"Decrypted {Path(in_path).name} -> {Path(out_path).name}"
            )
            messagebox.showinfo(
                "Decryption complete",
                f"Recovered {metadata.original_filename}\n"
                f"Size: {metadata.original_size_bytes} bytes",
            )

    return SecureTrackApp


def main() -> None:
    """Entry point for ``python -m securetrack.gui``."""
    app_cls = _make_app_class()
    app_cls().mainloop()


if __name__ == "__main__":
    main()
