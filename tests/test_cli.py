"""End-to-end tests for the CLI subcommands."""

from __future__ import annotations

from pathlib import Path

import pytest

from securetrack import cli


def _wav(path: Path, payload: bytes = b"AUDIO" * 1024) -> Path:
    path.write_bytes(payload)
    return path


def test_keygen_x25519_writes_files(tmp_path: Path) -> None:
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    rc = cli.main(
        [
            "keygen",
            "--kind", "x25519",
            "--private-out", str(priv),
            "--public-out", str(pub),
        ]
    )
    assert rc == 0
    assert priv.exists() and pub.exists()
    assert b"BEGIN PRIVATE KEY" in priv.read_bytes()


def test_encrypt_then_decrypt_with_passphrase(tmp_path: Path) -> None:
    src = _wav(tmp_path / "in.wav")
    pkg = tmp_path / "out.securetrack"
    out = tmp_path / "recovered.wav"

    rc_enc = cli.main(
        [
            "encrypt",
            "-i", str(src),
            "-o", str(pkg),
            "-p", "test-pp",
        ]
    )
    assert rc_enc == 0 and pkg.exists()

    rc_dec = cli.main(
        [
            "decrypt",
            "-i", str(pkg),
            "-o", str(out),
            "-p", "test-pp",
        ]
    )
    assert rc_dec == 0
    assert out.read_bytes() == src.read_bytes()


def test_encrypt_then_decrypt_with_pubkey(tmp_path: Path) -> None:
    priv = tmp_path / "alice.pem"
    pub = tmp_path / "alice_pub.pem"
    cli.main(
        [
            "keygen",
            "--kind", "x25519",
            "--private-out", str(priv),
            "--public-out", str(pub),
        ]
    )
    src = _wav(tmp_path / "in.wav")
    pkg = tmp_path / "out.securetrack"
    out = tmp_path / "recovered.wav"

    cli.main(
        [
            "encrypt",
            "-i", str(src),
            "-o", str(pkg),
            "--recipient", str(pub),
        ]
    )
    cli.main(
        [
            "decrypt",
            "-i", str(pkg),
            "-o", str(out),
            "--key", str(priv),
        ]
    )
    assert out.read_bytes() == src.read_bytes()


def test_encrypt_with_signing_key_then_verify(tmp_path: Path) -> None:
    pp_pub = tmp_path / "verify.pem"
    pp_priv = tmp_path / "sign.pem"
    cli.main(
        [
            "keygen",
            "--kind", "ed25519",
            "--private-out", str(pp_priv),
            "--public-out", str(pp_pub),
        ]
    )
    src = _wav(tmp_path / "in.wav")
    pkg = tmp_path / "out.securetrack"
    out = tmp_path / "recovered.wav"

    cli.main(
        [
            "encrypt",
            "-i", str(src),
            "-o", str(pkg),
            "-p", "pp",
            "--signing-key", str(pp_priv),
            "--label", "project=demo",
            "--label", "take=1",
            "--creator-name", "alice",
        ]
    )
    rc = cli.main(
        [
            "decrypt",
            "-i", str(pkg),
            "-o", str(out),
            "-p", "pp",
            "--expect-signed-by", str(pp_pub),
        ]
    )
    assert rc == 0
    assert out.read_bytes() == src.read_bytes()


def test_decrypt_with_wrong_passphrase_returns_error_code(tmp_path: Path) -> None:
    src = _wav(tmp_path / "in.wav")
    pkg = tmp_path / "out.securetrack"
    out = tmp_path / "recovered.wav"
    cli.main(["encrypt", "-i", str(src), "-o", str(pkg), "-p", "right"])
    rc = cli.main(["decrypt", "-i", str(pkg), "-o", str(out), "-p", "wrong"])
    assert rc == 3


def test_inspect_does_not_decrypt(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    src = _wav(tmp_path / "in.wav")
    pkg = tmp_path / "out.securetrack"
    cli.main(["encrypt", "-i", str(src), "-o", str(pkg), "-p", "pp"])
    rc = cli.main(["inspect", "-i", str(pkg), "--json"])
    captured = capsys.readouterr()
    assert rc == 0
    assert '"format_version":2' in captured.out
    assert '"original_filename":"in.wav"' in captured.out
