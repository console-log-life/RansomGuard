"""
test_simulator.py

WHAT: tests the attack simulator and its undo script.

WHY : two things must be guaranteed before we let this run in a demo:
        1. SAFETY - it refuses any target outside the sandbox, and leaves outside files
           untouched;
        2. REVERSIBILITY - whatever it encrypts, undo.py restores byte-for-byte, because a
           saved key plus GCM means the round-trip is exact or it fails loudly.
      It also checks the encrypted output really looks like ransomware (high entropy, no
      magic bytes), since that is what the detector in later phases keys on.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ransomguard import config, entropy
from simulator import fake_ransomware, undo


@pytest.fixture
def sandbox_corpus(tmp_path, monkeypatch):
    """Point the whole project at a throwaway sandbox under tmp_path and fill it."""
    sandbox = tmp_path / "sandbox"
    protected = sandbox / "protected"
    protected.mkdir(parents=True)

    # Redirect every sandbox path the simulator/undo touch to this temp sandbox.
    monkeypatch.setattr(config, "SANDBOX", sandbox)
    monkeypatch.setattr(config, "PROTECTED_DIR", protected)
    monkeypatch.setattr(config, "BACKUP_DIR", sandbox / ".backup")
    monkeypatch.setattr(config, "SIM_KEY_FILE", sandbox / "sim_key.bin")

    (protected / "notes.txt").write_text("the quick brown fox " * 50, encoding="utf-8")
    (protected / "sub").mkdir()
    (protected / "sub" / "report.pdf").write_bytes(b"%PDF-1.4\n" + b"content " * 100)
    (protected / "photo.jpg").write_bytes(b"\xff\xd8\xff\xe0" + os.urandom(2000))
    return sandbox, protected


def _snapshot(folder: Path) -> dict[str, bytes]:
    return {
        str(p.relative_to(folder)): p.read_bytes()
        for p in folder.rglob("*")
        if p.is_file()
    }


def test_simulator_then_undo_restores_bytes_exactly(sandbox_corpus):
    _, protected = sandbox_corpus
    before = _snapshot(protected)

    rc = fake_ransomware.main(["--path", str(protected), "--delay", "0", "--order", "asis"])
    assert rc == 0

    # After the attack: no originals, only .locked files, and the key exists.
    after_attack = _snapshot(protected)
    assert all(name.endswith(".locked") for name in after_attack)
    assert len(after_attack) == len(before)
    assert config.SIM_KEY_FILE.exists()

    rc = undo.main(["--path", str(protected), "--key", str(config.SIM_KEY_FILE)])
    assert rc == 0

    assert _snapshot(protected) == before  # byte-for-byte round trip


def test_locked_output_looks_like_ransomware(sandbox_corpus):
    _, protected = sandbox_corpus
    fake_ransomware.main(["--path", str(protected), "--delay", "0", "--order", "asis"])

    locked_pdf = next(protected.rglob("report.pdf.locked"))
    data = locked_pdf.read_bytes()
    # Ciphertext body is high entropy; strip our small plaintext header first.
    body = data[-4096:] if len(data) > 4096 else data
    assert entropy.shannon_entropy(body) > 7.0
    # The .locked extension has no known magic signature -> unknown, never a false "ok".
    assert entropy.magic_bytes_ok(locked_pdf) is None


def test_simulator_refuses_target_outside_sandbox(tmp_path, capsys):
    outside = tmp_path / "victim_docs"
    outside.mkdir()
    (outside / "important.txt").write_text("do not touch", encoding="utf-8")

    rc = fake_ransomware.main(["--path", str(outside)])

    assert rc == 2
    assert "REFUSED" in capsys.readouterr().out
    # The outside file is completely untouched.
    assert (outside / "important.txt").read_text(encoding="utf-8") == "do not touch"


def test_dry_run_changes_nothing(sandbox_corpus):
    _, protected = sandbox_corpus
    before = _snapshot(protected)

    rc = fake_ransomware.main(["--path", str(protected), "--dry-run"])

    assert rc == 0
    assert _snapshot(protected) == before
    assert not config.SIM_KEY_FILE.exists()  # dry run never generates a key


def test_count_limits_number_of_files_encrypted(sandbox_corpus):
    _, protected = sandbox_corpus
    fake_ransomware.main(
        ["--path", str(protected), "--delay", "0", "--order", "asis", "--count", "1"]
    )
    locked = list(protected.rglob("*.locked"))
    plain = [p for p in protected.rglob("*") if p.is_file() and p.suffix != ".locked"]
    assert len(locked) == 1
    assert len(plain) == 2  # the other two originals remain untouched


def test_undo_with_no_locked_files_is_a_noop(sandbox_corpus):
    _, protected = sandbox_corpus
    config.SIM_KEY_FILE.write_bytes(b"\x00" * 32)
    before = _snapshot(protected)
    rc = undo.main(["--path", str(protected), "--key", str(config.SIM_KEY_FILE)])
    assert rc == 0
    assert _snapshot(protected) == before


def test_undo_without_key_fails_cleanly(sandbox_corpus):
    _, protected = sandbox_corpus
    fake_ransomware.main(["--path", str(protected), "--delay", "0", "--order", "asis"])
    config.SIM_KEY_FILE.unlink()  # simulate a lost key
    rc = undo.main(["--path", str(protected), "--key", str(config.SIM_KEY_FILE)])
    assert rc == 1  # reports failure, does not crash
