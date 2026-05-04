"""Tests for the metrics helpers and the end-to-end benchmark."""

from __future__ import annotations

import csv
from pathlib import Path

from securetrack import benchmark, metrics


# --- pure metric helpers ---------------------------------------------------


def test_size_overhead_bytes() -> None:
    assert metrics.size_overhead_bytes(1000, 1240) == 240
    assert metrics.size_overhead_bytes(0, 0) == 0


def test_size_overhead_percent_basic() -> None:
    assert metrics.size_overhead_percent(1000, 1100) == 10.0
    assert metrics.size_overhead_percent(2000, 2500) == 25.0


def test_size_overhead_percent_zero_original_does_not_divide_by_zero() -> None:
    assert metrics.size_overhead_percent(0, 100) == 0.0


def test_throughput_basic() -> None:
    # 1 MB in 1 second == 1 MB/s exactly.
    assert metrics.throughput_mbps(metrics.BYTES_PER_MB, 1.0) == 1.0


def test_throughput_zero_seconds_returns_zero() -> None:
    assert metrics.throughput_mbps(1_000_000, 0.0) == 0.0
    assert metrics.throughput_mbps(1_000_000, -1.0) == 0.0


# --- end to end benchmark --------------------------------------------------


def test_run_benchmark_roundtrip(tmp_path: Path) -> None:
    src = tmp_path / "in.wav"
    src.write_bytes(b"\x01\x02\x03\x04" * 4096)
    result = benchmark.run_benchmark(src, "passphrase!")

    assert result.hash_match is True
    assert result.tamper_detection_passed is True
    assert result.original_size_bytes == src.stat().st_size
    assert result.encrypted_size_bytes > result.original_size_bytes
    assert result.size_overhead_bytes == (
        result.encrypted_size_bytes - result.original_size_bytes
    )
    assert result.encryption_time_seconds > 0.0
    assert result.decryption_time_seconds > 0.0
    assert result.algorithm == "AES-256-GCM"
    assert result.kdf == "scrypt"


def test_append_metrics_to_csv_writes_header_then_appends(tmp_path: Path) -> None:
    src = tmp_path / "in.wav"
    src.write_bytes(b"abc" * 1024)
    csv_path = tmp_path / "metrics.csv"

    first = benchmark.run_benchmark(src, "pp")
    benchmark.append_metrics_to_csv(first, csv_path)
    second = benchmark.run_benchmark(src, "pp")
    benchmark.append_metrics_to_csv(second, csv_path)

    with csv_path.open("r", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    assert len(rows) == 2
    assert set(rows[0].keys()) == set(metrics.CSV_FIELDNAMES)
    assert rows[0]["hash_match"] == "true"
    assert rows[0]["tamper_detection_passed"] == "true"
    assert rows[0]["algorithm"] == "AES-256-GCM"
