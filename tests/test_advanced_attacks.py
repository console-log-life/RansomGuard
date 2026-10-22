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
import subprocess
import sys
from pathlib import Path

import pytest

from ransomguard import config, entropy
from ransomguard.baseline import BaselineEntry
from ransomguard.scorer import evaluate_signals

PY = sys.executable
ROOT = Path(__file__).resolve().parent.parent


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
def test_simulator_never_encrypts_recovery_keys(mode):
    """No attack mode may touch backup_key.bin or the manifest - recovery must stay possible.

    Runs against the real sandbox (safe: sandbox-only), building a backup first so the key
    and manifest exist, then attacking and checking both are byte-identical afterwards.
    """
    subprocess.run([PY, "tools/make_test_files.py", "--clean"], cwd=ROOT,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    # Create the protected key + manifest by building a backup.
    subprocess.run(
        [PY, "-c", "import sys; sys.path.insert(0,'.'); from ransomguard import backup; backup.build_backup()"],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
    )
    key_before = config.BACKUP_KEY_FILE.read_bytes()
    manifest_before = config.MANIFEST_FILE.read_bytes()

    subprocess.run(
        [PY, "-m", "simulator.fake_ransomware", "--mode", mode, "--delay", "0", "--order", "asis"],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    assert config.BACKUP_KEY_FILE.read_bytes() == key_before, f"{mode} touched the backup key!"
    assert config.MANIFEST_FILE.read_bytes() == manifest_before, f"{mode} touched the manifest!"
    # tidy up
    subprocess.run([PY, "-m", "simulator.undo"], cwd=ROOT,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
