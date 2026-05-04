"""Generate small synthetic WAV files for development and benchmarking.

The dissertation must not include any real, copyrighted music in the
repository, so this script synthesises tiny test signals using only the
Python standard library.

Run it from the repository root::

    python examples/generate_sample_wavs.py

It writes three files into ``examples/`` (which is excluded from git
via ``.gitignore``):

* ``sample.wav``        - 2 seconds of a 440 Hz sine, mono, 16-bit, 44.1 kHz.
* ``sample_stereo.wav`` - 2 seconds of a 440 Hz / 660 Hz sine pair.
* ``sample_silence.wav`` - 2 seconds of silence (useful as a degenerate test).
"""

from __future__ import annotations

import math
import struct
import wave
from pathlib import Path

SAMPLE_RATE: int = 44_100
DURATION_SECONDS: float = 2.0
SAMPLE_WIDTH_BYTES: int = 2  # 16-bit signed PCM
MAX_AMPLITUDE: int = 2**15 - 1  # signed 16-bit


def _write_wav(
    path: Path,
    *,
    num_channels: int,
    samples_per_channel: list[list[int]],
) -> None:
    """Write a 16-bit PCM WAV from a per-channel list of samples."""
    if num_channels != len(samples_per_channel):
        raise ValueError("samples_per_channel must contain one list per channel")
    n = len(samples_per_channel[0])
    if any(len(c) != n for c in samples_per_channel):
        raise ValueError("all channels must have the same length")

    interleaved = bytearray()
    for i in range(n):
        for ch in samples_per_channel:
            interleaved.extend(struct.pack("<h", ch[i]))

    with wave.open(str(path), "wb") as wav:
        wav.setnchannels(num_channels)
        wav.setsampwidth(SAMPLE_WIDTH_BYTES)
        wav.setframerate(SAMPLE_RATE)
        wav.writeframes(bytes(interleaved))


def _sine_samples(frequency: float, duration: float, *, amplitude: float = 0.6) -> list[int]:
    """Return signed 16-bit PCM samples for a sine wave."""
    n = int(duration * SAMPLE_RATE)
    scale = amplitude * MAX_AMPLITUDE
    two_pi_f = 2.0 * math.pi * frequency
    return [int(scale * math.sin(two_pi_f * (i / SAMPLE_RATE))) for i in range(n)]


def _silence_samples(duration: float) -> list[int]:
    return [0] * int(duration * SAMPLE_RATE)


def generate_all(output_dir: Path | None = None) -> list[Path]:
    """Generate all sample WAVs and return the list of paths written."""
    out = Path(output_dir) if output_dir is not None else Path(__file__).parent
    out.mkdir(parents=True, exist_ok=True)

    mono_path = out / "sample.wav"
    _write_wav(
        mono_path,
        num_channels=1,
        samples_per_channel=[_sine_samples(440.0, DURATION_SECONDS)],
    )

    stereo_path = out / "sample_stereo.wav"
    _write_wav(
        stereo_path,
        num_channels=2,
        samples_per_channel=[
            _sine_samples(440.0, DURATION_SECONDS),
            _sine_samples(660.0, DURATION_SECONDS),
        ],
    )

    silence_path = out / "sample_silence.wav"
    _write_wav(
        silence_path,
        num_channels=1,
        samples_per_channel=[_silence_samples(DURATION_SECONDS)],
    )

    return [mono_path, stereo_path, silence_path]


def main() -> None:
    paths = generate_all()
    for p in paths:
        size = p.stat().st_size
        print(f"wrote {p} ({size:,} bytes)")


if __name__ == "__main__":
    main()
