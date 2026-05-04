"""Pure helpers for computing the performance metrics reported by SecureTrack.

These functions are intentionally side-effect free so they can be unit
tested without any cryptography or I/O.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Number of bytes in one megabyte (decimal MB, the convention used in
#: most networking / storage contexts and in the dissertation).
BYTES_PER_MB: int = 1_000_000


@dataclass(frozen=True)
class BenchmarkMetrics:
    """Aggregated metrics produced by :func:`benchmark.run_benchmark`."""

    timestamp: str
    input_file: str
    original_size_bytes: int
    encrypted_size_bytes: int
    size_overhead_bytes: int
    size_overhead_percent: float
    encryption_time_seconds: float
    decryption_time_seconds: float
    encryption_throughput_MBps: float
    decryption_throughput_MBps: float
    sha256_original: str
    sha256_decrypted: str
    hash_match: bool
    tamper_detection_passed: bool
    algorithm: str
    kdf: str

    def as_csv_row(self) -> dict[str, str]:
        """Return the metrics as a dict of strings ready for ``csv.DictWriter``."""
        return {
            "timestamp": self.timestamp,
            "input_file": self.input_file,
            "original_size_bytes": str(self.original_size_bytes),
            "encrypted_size_bytes": str(self.encrypted_size_bytes),
            "size_overhead_bytes": str(self.size_overhead_bytes),
            "size_overhead_percent": f"{self.size_overhead_percent:.4f}",
            "encryption_time_seconds": f"{self.encryption_time_seconds:.6f}",
            "decryption_time_seconds": f"{self.decryption_time_seconds:.6f}",
            "encryption_throughput_MBps": f"{self.encryption_throughput_MBps:.4f}",
            "decryption_throughput_MBps": f"{self.decryption_throughput_MBps:.4f}",
            "sha256_original": self.sha256_original,
            "sha256_decrypted": self.sha256_decrypted,
            "hash_match": "true" if self.hash_match else "false",
            "tamper_detection_passed": "true" if self.tamper_detection_passed else "false",
            "algorithm": self.algorithm,
            "kdf": self.kdf,
        }


CSV_FIELDNAMES: tuple[str, ...] = (
    "timestamp",
    "input_file",
    "original_size_bytes",
    "encrypted_size_bytes",
    "size_overhead_bytes",
    "size_overhead_percent",
    "encryption_time_seconds",
    "decryption_time_seconds",
    "encryption_throughput_MBps",
    "decryption_throughput_MBps",
    "sha256_original",
    "sha256_decrypted",
    "hash_match",
    "tamper_detection_passed",
    "algorithm",
    "kdf",
)


def size_overhead_bytes(original_size: int, encrypted_size: int) -> int:
    """Return ``encrypted_size - original_size`` (may be negative in theory)."""
    return encrypted_size - original_size


def size_overhead_percent(original_size: int, encrypted_size: int) -> float:
    """Return the percentage overhead added by the package, relative to the original.

    The overhead is defined as ``(encrypted - original) / original * 100``.
    Returns ``0.0`` when ``original_size`` is zero, to avoid a division by
    zero error - this is a corner case that should never appear in
    practice for real audio files.
    """
    if original_size == 0:
        return 0.0
    return (encrypted_size - original_size) / original_size * 100.0


def throughput_mbps(num_bytes: int, seconds: float) -> float:
    """Return throughput in megabytes-per-second.

    Uses the decimal definition of a megabyte (1,000,000 bytes). Returns
    ``0.0`` when ``seconds`` is non-positive to keep the metric
    well-defined for trivially small inputs.
    """
    if seconds <= 0:
        return 0.0
    return (num_bytes / BYTES_PER_MB) / seconds
