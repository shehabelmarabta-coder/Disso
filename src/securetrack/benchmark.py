"""End-to-end performance and correctness benchmark.

The :func:`run_benchmark` function wires together the crypto, package and
metrics modules to produce a :class:`metrics.BenchmarkMetrics` row that
captures everything the dissertation evaluation chapter needs about a
single encrypt / decrypt round-trip:

1. Read the input WAV file.
2. Encrypt it into a ``.securetrack`` package (timed).
3. Decrypt the package back to plaintext (timed).
4. Verify SHA-256 equality.
5. Run a tamper test by flipping one byte of the package and confirming
   that decryption fails.
6. Compute size and throughput metrics.

The benchmark is deliberately simple - one run, single-threaded - because
the dissertation is more interested in *correctness* and *order of
magnitude* performance than in micro-benchmarking. If finer numbers are
needed later, a caller can simply invoke :func:`run_benchmark` in a loop
and aggregate the rows in pandas.
"""

from __future__ import annotations

import csv
import datetime as dt
import hashlib
import time
from pathlib import Path

from . import crypto, package
from .metrics import (
    CSV_FIELDNAMES,
    BenchmarkMetrics,
    size_overhead_bytes,
    size_overhead_percent,
    throughput_mbps,
)


def _utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _flip_one_byte(data: bytes, *, offset: int = -32) -> bytes:
    """Return ``data`` with the byte at ``offset`` toggled.

    The default ``offset`` of ``-32`` reaches into the AES-GCM tag region
    of a ``.securetrack`` package, which is reliably modified by ZIP's
    central directory layout. Any single-byte change anywhere inside the
    ciphertext / tag must cause authentication to fail; this helper is
    just a convenient default.
    """
    if not data:
        raise ValueError("cannot tamper with an empty byte string")
    idx = offset if offset >= 0 else len(data) + offset
    if not 0 <= idx < len(data):
        raise ValueError(f"tamper offset {offset} is out of range for length {len(data)}")
    mutable = bytearray(data)
    mutable[idx] ^= 0x01
    return bytes(mutable)


def run_benchmark(input_path: Path, passphrase: str) -> BenchmarkMetrics:
    """Run a single encrypt/decrypt benchmark and return the collected metrics."""
    input_path = Path(input_path)
    plaintext = input_path.read_bytes()
    sha_original = hashlib.sha256(plaintext).hexdigest()

    # --- encryption ------------------------------------------------------
    t0 = time.perf_counter()
    package_bytes = package.pack(
        plaintext,
        passphrase,
        original_filename=input_path.name,
    )
    enc_seconds = time.perf_counter() - t0

    # --- decryption ------------------------------------------------------
    t0 = time.perf_counter()
    _, decrypted = package.unpack(package_bytes, passphrase)
    dec_seconds = time.perf_counter() - t0
    sha_decrypted = hashlib.sha256(decrypted).hexdigest()

    # --- tamper detection -----------------------------------------------
    tampered = _flip_one_byte(package_bytes)
    try:
        package.unpack(tampered, passphrase)
        tamper_detected = False  # Should have raised - this is a failure.
    except (crypto.InvalidPassphraseError, ValueError):
        tamper_detected = True

    # --- aggregate metrics ----------------------------------------------
    original_size = len(plaintext)
    encrypted_size = len(package_bytes)
    return BenchmarkMetrics(
        timestamp=_utc_now_iso(),
        input_file=str(input_path),
        original_size_bytes=original_size,
        encrypted_size_bytes=encrypted_size,
        size_overhead_bytes=size_overhead_bytes(original_size, encrypted_size),
        size_overhead_percent=size_overhead_percent(original_size, encrypted_size),
        encryption_time_seconds=enc_seconds,
        decryption_time_seconds=dec_seconds,
        encryption_throughput_MBps=throughput_mbps(original_size, enc_seconds),
        decryption_throughput_MBps=throughput_mbps(original_size, dec_seconds),
        sha256_original=sha_original,
        sha256_decrypted=sha_decrypted,
        hash_match=sha_original == sha_decrypted,
        tamper_detection_passed=tamper_detected,
        algorithm=crypto.ALGORITHM_NAME,
        kdf=crypto.KDF_NAME,
    )


def append_metrics_to_csv(metrics: BenchmarkMetrics, output_path: Path) -> None:
    """Append a benchmark row to ``output_path``, writing the header if needed."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not output_path.exists() or output_path.stat().st_size == 0

    with output_path.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDNAMES)
        if write_header:
            writer.writeheader()
        writer.writerow(metrics.as_csv_row())
