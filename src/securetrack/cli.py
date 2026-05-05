"""SecureTrack command line interface.

Subcommands::

    keygen           Generate an X25519 (encryption) or Ed25519 (signing) keypair.
    encrypt          Wrap a WAV in a .securetrack package (passphrase / pubkey
                     recipients, optional Ed25519 signature).
    decrypt          Unwrap a .securetrack package back into the original WAV.
    inspect          Print the metadata of a package without decrypting it.
    benchmark        One-shot encrypt+decrypt+tamper benchmark.
    audacity-test    Probe the Audacity mod-script-pipe and send a Help command.
    audacity-export  Export the active Audacity project and seal it in one step.

Run ``python -m securetrack.cli --help`` (or any subcommand with ``--help``)
for the full usage.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__, audacity_bridge, benchmark, crypto, keys, package, recipients


# --- helpers ---------------------------------------------------------------


def _resolve_passphrase(arg_value: str | None, *, prompt: str = "Passphrase: ") -> str:
    if arg_value:
        return arg_value
    pw = getpass.getpass(prompt)
    if not pw:
        raise SystemExit("error: empty passphrase is not allowed")
    return pw


def _maybe_passphrase(arg_value: str | None) -> str | None:
    return arg_value if arg_value else None


def _print_metadata(meta: package.PackageMetadata) -> None:
    print("  format version   :", meta.format_version)
    print("  algorithm        :", meta.algorithm)
    print("  kdf              :", meta.kdf)
    print("  chunk size       :", meta.chunk_size, "bytes")
    print("  num chunks       :", meta.num_chunks)
    print("  original filename:", meta.original_filename)
    print("  original size    :", meta.original_size_bytes, "bytes")
    print("  sha256 original  :", meta.sha256_original)
    print("  created (UTC)    :", meta.created_utc)
    print("  tool version     :", meta.tool_version)
    if meta.creator:
        print("  creator          :", meta.creator)
    if meta.labels:
        print("  labels           :", meta.labels)
    if meta.signature_algorithm:
        print("  signature alg    :", meta.signature_algorithm)


# --- subcommand: keygen ----------------------------------------------------


def cmd_keygen(args: argparse.Namespace) -> int:
    kind = args.kind.lower()
    if kind == "x25519":
        kp = keys.generate_x25519_keypair()
    elif kind == "ed25519":
        kp = keys.generate_ed25519_keypair()
    else:
        print(f"error: unknown key kind '{kind}' (expected x25519 or ed25519)",
              file=sys.stderr)
        return 2

    pass_for_priv = args.private_passphrase
    if args.encrypt_private and not pass_for_priv:
        pass_for_priv = getpass.getpass("Passphrase to encrypt the private key: ")

    keys.write_keypair(
        kp,
        private_path=Path(args.private_out),
        public_path=Path(args.public_out),
        passphrase=pass_for_priv,
    )
    print(f"Wrote {kind} private key -> {args.private_out}")
    print(f"Wrote {kind} public  key -> {args.public_out}")
    return 0


# --- subcommand: encrypt ---------------------------------------------------


def _gather_recipients(args: argparse.Namespace) -> list[recipients.RecipientSpec]:
    specs: list[recipients.RecipientSpec] = []

    for pub_path in args.recipient or []:
        try:
            pub = keys.load_x25519_public(Path(pub_path))
        except (ValueError, OSError) as exc:
            raise SystemExit(f"error: cannot load recipient public key {pub_path}: {exc}")
        specs.append(
            recipients.PublicKeyRecipient(public_key=pub, label=Path(pub_path).stem)
        )

    if args.passphrase or args.passphrase_recipient:
        pp = args.passphrase or getpass.getpass(
            "Passphrase recipient (chosen by sender): "
        )
        if not pp:
            raise SystemExit("error: empty passphrase is not allowed")
        specs.append(recipients.PassphraseRecipient(passphrase=pp))

    if not specs:
        raise SystemExit(
            "error: at least one recipient is required "
            "(use --recipient PUB.pem and/or --passphrase / --passphrase-recipient)"
        )
    return specs


def _gather_labels(arg_values: list[str] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in arg_values or []:
        if "=" not in raw:
            raise SystemExit(f"error: --label expects key=value, got '{raw}'")
        k, v = raw.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def cmd_encrypt(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    output_path = Path(args.output)
    if not input_path.is_file():
        print(f"error: input file not found: {input_path}", file=sys.stderr)
        return 2

    specs = _gather_recipients(args)
    labels = _gather_labels(args.label)
    creator = {}
    if args.creator_name:
        creator["name"] = args.creator_name

    signing_key = None
    if args.signing_key:
        try:
            signing_key = keys.load_ed25519_private(
                Path(args.signing_key),
                passphrase=args.signing_key_passphrase,
            )
        except (ValueError, OSError) as exc:
            print(f"error: cannot load signing key: {exc}", file=sys.stderr)
            return 2

    output_path.parent.mkdir(parents=True, exist_ok=True)
    metadata = package.encrypt_file(
        input_path,
        output_path,
        recipient_specs=specs,
        labels=labels,
        creator=creator,
        chunk_size=args.chunk_size,
        signing_key=signing_key,
    )
    print(f"Encrypted {input_path} -> {output_path}")
    _print_metadata(metadata)
    return 0


# --- subcommand: decrypt ---------------------------------------------------


def cmd_decrypt(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    output_path = Path(args.output)
    if not input_path.is_file():
        print(f"error: input file not found: {input_path}", file=sys.stderr)
        return 2

    private_key = None
    if args.key:
        try:
            private_key = keys.load_x25519_private(
                Path(args.key), passphrase=args.key_passphrase
            )
        except (ValueError, OSError) as exc:
            print(f"error: cannot load private key: {exc}", file=sys.stderr)
            return 2

    passphrase = _maybe_passphrase(args.passphrase)
    if private_key is None and passphrase is None:
        passphrase = getpass.getpass("Passphrase: ") or None
        if passphrase is None:
            print("error: provide --key PRIV.pem and/or --passphrase", file=sys.stderr)
            return 2

    expected_signing_pubkey = None
    if args.expect_signed_by:
        try:
            expected_signing_pubkey = keys.load_ed25519_public(
                Path(args.expect_signed_by)
            )
        except (ValueError, OSError) as exc:
            print(f"error: cannot load signing public key: {exc}", file=sys.stderr)
            return 2

    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        metadata = package.decrypt_file(
            input_path,
            output_path,
            passphrase=passphrase,
            private_key=private_key,
            expected_signing_pubkey=expected_signing_pubkey,
        )
    except crypto.InvalidPassphraseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except crypto.InvalidSignatureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 5
    except ValueError as exc:
        print(f"error: malformed package: {exc}", file=sys.stderr)
        return 4

    print(f"Decrypted {input_path} -> {output_path}")
    _print_metadata(metadata)
    return 0


# --- subcommand: inspect ---------------------------------------------------


def cmd_inspect(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    if not input_path.is_file():
        print(f"error: input file not found: {input_path}", file=sys.stderr)
        return 2
    try:
        metadata = package.read_metadata(input_path)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4
    if args.json:
        # Re-serialise the canonical JSON so the user sees exactly what
        # was authenticated.
        sys.stdout.write(metadata.to_json_bytes().decode("utf-8") + "\n")
    else:
        print(f"Package: {input_path}")
        _print_metadata(metadata)
    return 0


# --- subcommand: benchmark -------------------------------------------------


def cmd_benchmark(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    output_path = Path(args.output)
    if not input_path.is_file():
        print(f"error: input file not found: {input_path}", file=sys.stderr)
        return 2

    passphrase = _resolve_passphrase(args.passphrase)
    metrics = benchmark.run_benchmark(input_path, passphrase)
    benchmark.append_metrics_to_csv(metrics, output_path)
    print(f"Benchmark written to {output_path}")
    print(
        f"  encryption     : {metrics.encryption_time_seconds*1000:.1f} ms "
        f"({metrics.encryption_throughput_MBps:.2f} MB/s)"
    )
    print(
        f"  decryption     : {metrics.decryption_time_seconds*1000:.1f} ms "
        f"({metrics.decryption_throughput_MBps:.2f} MB/s)"
    )
    print(
        f"  size overhead  : {metrics.size_overhead_bytes} bytes "
        f"({metrics.size_overhead_percent:.4f}%)"
    )
    print(f"  hash match     : {metrics.hash_match}")
    print(f"  tamper detected: {metrics.tamper_detection_passed}")
    return 0 if (metrics.hash_match and metrics.tamper_detection_passed) else 1


# --- subcommand: audacity-test ---------------------------------------------


def cmd_audacity_test(args: argparse.Namespace) -> int:
    """Probe the Audacity bridge and send a single Help command."""
    status = audacity_bridge.runtime_status()
    print("SecureTrack <-> Audacity bridge status")
    print("--------------------------------------")
    for key in (
        "platform",
        "to_pipe",
        "from_pipe",
        "pywin32_installed",
        "pywin32_error",
        "available",
    ):
        if key in status:
            print(f"  {key:<20s}: {status[key]}")

    if status["available"] != "yes":
        print()
        print("Pipes are not available. Make sure Audacity is running with")
        print("mod-script-pipe enabled (Edit ▸ Preferences ▸ Modules), and")
        print("on Windows that pywin32 is installed (`pip install pywin32`).")
        return 6

    print()
    print("Connecting and sending: Help: Command=Help")
    try:
        with audacity_bridge.AudacityScriptPipe.connect(timeout_seconds=args.timeout) as pipe:
            response = pipe.ping()
    except audacity_bridge.AudacityPipeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 7

    print("---- Audacity response ----")
    sys.stdout.write(response)
    if not response.endswith("\n"):
        print()
    print("---------------------------")
    return 0


# --- subcommand: audacity-export -------------------------------------------


def cmd_audacity_export(args: argparse.Namespace) -> int:
    """Drive Audacity to export the project, then encrypt the WAV."""
    output_path = Path(args.output)
    specs = _gather_recipients(args)

    signing_key = None
    if args.signing_key:
        try:
            signing_key = keys.load_ed25519_private(
                Path(args.signing_key),
                passphrase=args.signing_key_passphrase,
            )
        except (ValueError, OSError) as exc:
            print(f"error: cannot load signing key: {exc}", file=sys.stderr)
            return 2

    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = audacity_bridge.secure_export_from_audacity(
            output_path,
            recipient_specs=specs,
            labels=_gather_labels(args.label),
            creator={"name": args.creator_name} if args.creator_name else None,
            signing_key=signing_key,
            num_channels=args.num_channels,
            select_all=not args.no_select_all,
        )
    except audacity_bridge.AudacityPipeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 7
    print(f"Exported and encrypted -> {result}")
    return 0


# --- argument parser -------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securetrack",
        description="Encrypt, decrypt and benchmark .securetrack audio packages.",
    )
    parser.add_argument("--version", action="version", version=f"securetrack {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    # keygen
    kg = sub.add_parser("keygen", help="generate an X25519 or Ed25519 keypair")
    kg.add_argument("--kind", choices=["x25519", "ed25519"], required=True)
    kg.add_argument("--private-out", required=True, help="path to write the private key (PEM)")
    kg.add_argument("--public-out", required=True, help="path to write the public key (PEM)")
    kg.add_argument(
        "--encrypt-private",
        action="store_true",
        help="prompt for a passphrase and store the private key encrypted at rest",
    )
    kg.add_argument(
        "--private-passphrase",
        help="passphrase for the private key (prompted if --encrypt-private and omitted)",
    )
    kg.set_defaults(func=cmd_keygen)

    # encrypt
    enc = sub.add_parser("encrypt", help="encrypt an audio file into a .securetrack package")
    enc.add_argument("--input", "-i", required=True, help="input audio file (WAV)")
    enc.add_argument("--output", "-o", required=True, help="output .securetrack file")
    enc.add_argument(
        "--recipient",
        action="append",
        metavar="PUB.pem",
        help="add an X25519 public-key recipient (may be given multiple times)",
    )
    enc.add_argument(
        "--passphrase", "-p",
        help="add a passphrase recipient with this passphrase",
    )
    enc.add_argument(
        "--passphrase-recipient",
        action="store_true",
        help="add a passphrase recipient, prompting for the passphrase",
    )
    enc.add_argument(
        "--signing-key",
        metavar="PRIV.pem",
        help="path to an Ed25519 private key; sign the package with it",
    )
    enc.add_argument("--signing-key-passphrase", help="passphrase for the signing key")
    enc.add_argument(
        "--chunk-size",
        type=int,
        default=crypto.DEFAULT_CHUNK_SIZE,
        help=f"AEAD chunk size in bytes (default {crypto.DEFAULT_CHUNK_SIZE})",
    )
    enc.add_argument(
        "--label",
        action="append",
        metavar="key=value",
        help="add a free-form label (may be given multiple times)",
    )
    enc.add_argument("--creator-name", help="creator name to record in the metadata")
    enc.set_defaults(func=cmd_encrypt)

    # decrypt
    dec = sub.add_parser("decrypt", help="decrypt a .securetrack package back to audio")
    dec.add_argument("--input", "-i", required=True, help="input .securetrack file")
    dec.add_argument("--output", "-o", required=True, help="output audio file")
    dec.add_argument("--passphrase", "-p", help="recipient passphrase (prompted if omitted)")
    dec.add_argument(
        "--key",
        metavar="PRIV.pem",
        help="path to an X25519 private key for a pubkey recipient",
    )
    dec.add_argument("--key-passphrase", help="passphrase for the X25519 private key")
    dec.add_argument(
        "--expect-signed-by",
        metavar="PUB.pem",
        help="require the package to be signed by this Ed25519 public key",
    )
    dec.set_defaults(func=cmd_decrypt)

    # inspect
    insp = sub.add_parser("inspect", help="print the metadata of a package without decrypting")
    insp.add_argument("--input", "-i", required=True)
    insp.add_argument("--json", action="store_true", help="emit canonical JSON")
    insp.set_defaults(func=cmd_inspect)

    # benchmark
    bench = sub.add_parser("benchmark", help="run an encrypt/decrypt benchmark")
    bench.add_argument("--input", "-i", required=True, help="input audio file")
    bench.add_argument("--output", "-o", required=True, help="CSV file to append results to")
    bench.add_argument("--passphrase", "-p", help="passphrase (will prompt if omitted)")
    bench.set_defaults(func=cmd_benchmark)

    # audacity-test
    at = sub.add_parser(
        "audacity-test",
        help="probe the Audacity mod-script-pipe and run a Help command",
    )
    at.add_argument(
        "--timeout", type=float, default=5.0, help="connection timeout in seconds"
    )
    at.set_defaults(func=cmd_audacity_test)

    # audacity-export
    ax = sub.add_parser(
        "audacity-export",
        help="drive Audacity to export the active project and seal the WAV",
    )
    ax.add_argument("--output", "-o", required=True, help="output .securetrack file")
    ax.add_argument(
        "--recipient", action="append", metavar="PUB.pem",
        help="X25519 public-key recipient (may be given multiple times)",
    )
    ax.add_argument("--passphrase", "-p", help="passphrase recipient")
    ax.add_argument(
        "--passphrase-recipient", action="store_true",
        help="prompt for a passphrase recipient",
    )
    ax.add_argument("--signing-key", metavar="PRIV.pem", help="Ed25519 signing key")
    ax.add_argument("--signing-key-passphrase", help="passphrase for signing key")
    ax.add_argument(
        "--label", action="append", metavar="key=value",
        help="add a free-form label (may be given multiple times)",
    )
    ax.add_argument("--creator-name", help="creator name to record in the metadata")
    ax.add_argument(
        "--num-channels", type=int, default=2,
        help="channel count for Audacity Export2 (default 2)",
    )
    ax.add_argument(
        "--no-select-all", action="store_true",
        help="don't ask Audacity to SelectAll before exporting (export selection only)",
    )
    ax.set_defaults(func=cmd_audacity_export)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())


# Re-export so `python -m securetrack.cli` and module imports stay friendly.
__all__ = ["build_parser", "main"]


# Keep ``json`` from being flagged as unused (it is reserved for future
# enrichment of the inspect JSON output).
_ = json
