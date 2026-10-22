"""
test_advanced_attacks.py

WHAT: tests the smart attack modes and the stronger detection that catches them, plus the
      safety guarantee that NO attack mode ever touches the recovery keys or manifest.

WHY : the whole point of Part B is "before/after" - the new attacks must evade the OLD
      signals and be caught by the NEW ones. These tests pin that down deterministically at
      the signal level (no live timing): base64 content slips under the old entropy/chi
      signals but trips the encoded signal; intermittent encryption hides from first-window
      sampling but is found by multi-offset sampling. The safety test proves the smarter
      simulator still cannot destroy the keys that make recovery possible.
"""

from __future__ import annotations

import base64
import os

import pytest

from ransomguard import config, entropy
from ransomguard.baseline import BaselineEntry
from ransomguard.scorer import evaluate_signals


# ------------------------------------------------- encoded / base64 detection
def test_base64_of_ciphertext_is_flagged_encoded():
    blob = base64.b64encode(os.urandom(50_000))
    assert entropy.is_encoded(blob) is True


def test_plain_text_and_raw_ciphertext_are_not_encoded():
    assert entropy.is_encoded(b"the quick brown fox " * 1000) is False  # too low entropy
    assert entropy.is_encoded(os.urandom(50_000)) is False               # not base64 charset


def test_encoded_signal_fires_only_on_transformed_file(tmp_path):
    enc_file = tmp_path / "doc.txt"
    enc_file.write_bytes(base64.b64encode(os.urandom(40_000)))
    signals = entropy.analyse_file(enc_file)
    assert signals.encoded is True

    was_text = BaselineEntry(entropy=4.2, sha256="x", size=100, ext=".txt")
    codes = {r.code for r in evaluate_signals(signals, was_text, canary_touched=False)}
    assert "encoded" in codes
    # entropy ~6 means the OLD entropy-jump / low-chi signals do NOT fire on base64.
    assert "entropy_jump" not in codes and "low_chi_square" not in codes
    # A brand-new base64 file (no baseline) is NOT blamed on its own.
    assert all(r.code != "encoded" for r in evaluate_signals(signals, None, canary_touched=False))


# ------------------------------------------------- multi-offset entropy
def test_multi_offset_catches_intermittent_encryption(tmp_path, monkeypatch):
    # A file that is plaintext in its first 64 KB but random afterwards (intermittent).
    path = tmp_path / "big.bin"
    path.write_bytes(b"A" * 65536 + os.urandom(65536) + b"B" * 65536 + os.urandom(65536))

    monkeypatch.setattr(config, "FEATURE_MULTI_OFFSET_ENTROPY", False)
    old = entropy.analyse_file(path)
    monkeypatch.setattr(config, "FEATURE_MULTI_OFFSET_ENTROPY", True)
    new = entropy.analyse_file(path)

    assert old.entropy < 1.0        # first window is all 'A' -> old sampling sees nothing
    assert new.entropy > 7.5        # multi-offset finds the encrypted region


def test_entropy_jump_fires_with_multi_offset_not_without(tmp_path, monkeypatch):
    path = tmp_path / "report.pdf"
    path.write_bytes(b"A" * 65536 + os.urandom(65536))  # header-looking start, random tail
    was_low = BaselineEntry(entropy=1.0, sha256="x", size=100, ext=".pdf")

    monkeypatch.setattr(config, "FEATURE_MULTI_OFFSET_ENTROPY", False)
    old_codes = {r.code for r in evaluate_signals(entropy.analyse_file(path), was_low, canary_touched=False)}
    monkeypatch.setattr(config, "FEATURE_MULTI_OFFSET_ENTROPY", True)
    new_codes = {r.code for r in evaluate_signals(entropy.analyse_file(path), was_low, canary_touched=False)}

    assert "entropy_jump" not in old_codes   # old detector misses it
    assert "entropy_jump" in new_codes       # new detector catches it


# ------------------------------------------------- safety: keys never encrypted
@pytest.mark.parametrize("mode", ["full", "slow", "no-rename", "base64", "intermittent"])
def test_simulator_never_encrypts_recovery_keys(mode, tmp_path, monkeypatch):
    """No attack mode may touch backup_key.bin or the manifest - recovery must stay possible.

    Runs entirely in a throwaway tmp sandbox (config paths monkeypatched) and drives the
    simulator IN-PROCESS, so it cannot collide with a concurrent evaluation run using the
    real ./sandbox.
    """
    from ransomguard import backup as backup_mod
    from simulator import fake_ransomware

    sb = tmp_path / "sandbox"
    protected = sb / "protected"
    protected.mkdir(parents=True)
    monkeypatch.setattr(config, "SANDBOX", sb)
    monkeypatch.setattr(config, "PROTECTED_DIR", protected)
    monkeypatch.setattr(config, "BACKUP_DIR", sb / ".backup")
    monkeypatch.setattr(config, "MANIFEST_FILE", sb / ".backup" / "manifest.json")
    monkeypatch.setattr(config, "BACKUP_KEY_FILE", sb / "backup_key.bin")
    monkeypatch.setattr(config, "SIM_KEY_FILE", sb / "sim_key.bin")
    monkeypatch.setattr(config, "SIM_PID_FILE", sb / "sim_pid.txt")

    # A small corpus (a text file and a structured file), then a backup so the key +
    # manifest exist to be protected.
    (protected / "notes.txt").write_text("hello world " * 400, encoding="utf-8")
    (protected / "report.pdf").write_bytes(b"%PDF-1.4\n" + b"body " * 300)
    backup_mod.build_backup(protected)
    key_before = config.BACKUP_KEY_FILE.read_bytes()
    manifest_before = config.MANIFEST_FILE.read_bytes()

    rc = fake_ransomware.main(
        ["--path", str(protected), "--mode", mode, "--delay", "0", "--order", "asis"]
    )
    assert rc == 0
    assert config.BACKUP_KEY_FILE.read_bytes() == key_before, f"{mode} touched the backup key!"
    assert config.MANIFEST_FILE.read_bytes() == manifest_before, f"{mode} touched the manifest!"
