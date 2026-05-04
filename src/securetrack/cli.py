"""SecureTrack command line interface.

Three subcommands are supported:

``encrypt``
    Wrap a plaintext audio file in a ``.securetrack`` package.
``decrypt``
    Unwrap a ``.securetrack`` package back into the original audio file.
``benchmark``
    Run a one-shot encrypt/decrypt benchmark and append the metrics to
    a CSV file.

Run ``python -m securetrack.cli --help`` for the full usage.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__, benchmark, crypto, package


# --- helpers ---------------------------------------------------------------


def _resolve_passphrase(arg_value: str | None) -> str:
    """Return a passphrase from ``--passphrase`` or by prompting the user.

    The function never echoes the passphrase and never persists it.
    """
    if arg_value:
        return arg_value
    pw = getpass.getpass("Passphrase: ")
    if not pw:
        raise SystemExit("error: empty passphrase is not allowed")
    return pw


def _print_metadata(meta: package.PackageMetadata) -> None:
    print("  algorithm        :", meta.algorithm)
    print("  kdf              :", meta.kdf)
    print("  original filename:", meta.original_filename)
    print("  original size    :", meta.original_size_bytes, "bytes")
    print("  sha256 original  :", meta.sha256_original)
    print("  created (UTC)    :", meta.created_utc)
    if meta.labels:
        print("  labels           :", meta.labels)


# --- subcommand handlers ---------------------------------------------------


def cmd_encrypt(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    output_path = Path(args.output)
    if not input_path.is_file():
        print(f"error: input file not found: {input_path}", file=sys.stderr)
        return 2

    passphrase = _resolve_passphrase(args.passphrase)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    metadata = package.encrypt_file(input_path, output_path, passphrase)
    print(f"Encrypted {input_path} -> {output_path}")
    _print_metadata(metadata)
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    output_path = Path(args.output)
    if not input_path.is_file():
        print(f"error: input file not found: {input_path}", file=sys.stderr)
        return 2

    passphrase = _resolve_passphrase(args.passphrase)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        metadata = package.decrypt_file(input_path, output_path, passphrase)
    except crypto.InvalidPassphraseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except ValueError as exc:
        print(f"error: malformed package: {exc}", file=sys.stderr)
        return 4

    print(f"Decrypted {input_path} -> {output_path}")
    _print_metadata(metadata)
    return 0


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
    print(f"  encryption     : {metrics.encryption_time_seconds*1000:.1f} ms "
          f"({metrics.encryption_throughput_MBps:.2f} MB/s)")
    print(f"  decryption     : {metrics.decryption_time_seconds*1000:.1f} ms "
          f"({metrics.decryption_throughput_MBps:.2f} MB/s)")
    print(f"  size overhead  : {metrics.size_overhead_bytes} bytes "
          f"({metrics.size_overhead_percent:.4f}%)")
    print(f"  hash match     : {metrics.hash_match}")
    print(f"  tamper detected: {metrics.tamper_detection_passed}")
    return 0 if (metrics.hash_match and metrics.tamper_detection_passed) else 1


# --- argument parser -------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securetrack",
        description="Encrypt, decrypt and benchmark .securetrack audio packages.",
    )
    parser.add_argument("--version", action="version", version=f"securetrack {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encrypt", help="encrypt an audio file into a .securetrack package")
    enc.add_argument("--input", "-i", required=True, help="input audio file (WAV)")
    enc.add_argument("--output", "-o", required=True, help="output .securetrack file")
    enc.add_argument("--passphrase", "-p", help="passphrase (will prompt if omitted)")
    enc.set_defaults(func=cmd_encrypt)

    dec = sub.add_parser("decrypt", help="decrypt a .securetrack package back to audio")
    dec.add_argument("--input", "-i", required=True, help="input .securetrack file")
    dec.add_argument("--output", "-o", required=True, help="output audio file")
    dec.add_argument("--passphrase", "-p", help="passphrase (will prompt if omitted)")
    dec.set_defaults(func=cmd_decrypt)

    bench = sub.add_parser("benchmark", help="run an encrypt/decrypt benchmark")
    bench.add_argument("--input", "-i", required=True, help="input audio file")
    bench.add_argument("--output", "-o", required=True, help="CSV file to append results to")
    bench.add_argument("--passphrase", "-p", help="passphrase (will prompt if omitted)")
    bench.set_defaults(func=cmd_benchmark)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
