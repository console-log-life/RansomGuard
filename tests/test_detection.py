"""
test_detection.py

WHAT: tests baseline, canary and the end-to-end detection pipeline (monitor.handle_event),
      feeding it the same kind of events watchdog would, but synchronously.

WHY : this proves the three signals actually combine to catch the simulator and - just as
      important for the report - that a benign high-entropy file (an innocent new .jpg)
      does NOT raise an alert on its own. That false-positive guard is the whole reason for
      the weighted, multi-signal design.
"""

from __future__ import annotations

import os

import pytest

from ransomguard import baseline as baseline_mod
from ransomguard import canary as canary_mod
from ransomguard import config
from ransomguard.monitor import GLOBAL_ACTOR, RansomGuardMonitor
from ransomguard.logger import EventLogger


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    sb = tmp_path / "sandbox"
    protected = sb / "protected"
    (protected / "documents").mkdir(parents=True)
    monkeypatch.setattr(config, "SANDBOX", sb)
    monkeypatch.setattr(config, "PROTECTED_DIR", protected)
    monkeypatch.setattr(config, "BACKUP_DIR", sb / ".backup")
    monkeypatch.setattr(config, "MANIFEST_FILE", sb / ".backup" / "manifest.json")
    monkeypatch.setattr(config, "BACKUP_KEY_FILE", sb / "backup_key.bin")
    monkeypatch.setattr(config, "BASELINE_FILE", sb / "baseline.json")
    monkeypatch.setattr(config, "CANARY_FILE", sb / "canaries.json")
    monkeypatch.setattr(config, "LOG_FILE", sb / "events.jsonl")
    monkeypatch.setattr(config, "SIM_KEY_FILE", sb / "sim_key.bin")

    (protected / "documents" / "essay.txt").write_text("the lazy dog " * 300, encoding="utf-8")
    (protected / "report.pdf").write_bytes(b"%PDF-1.4\n" + b"text " * 500)
    return sb, protected


# --------------------------------------------------------------------- baseline
def test_baseline_records_hash_and_entropy(sandbox):
    _, protected = sandbox
    base = baseline_mod.build_baseline(protected)
    key = str((protected / "documents" / "essay.txt").resolve())
    assert key in base
    assert len(base[key].sha256) == 64
    assert base[key].entropy < 5.0


def test_baseline_round_trips_through_json(sandbox):
    _, protected = sandbox
    base = baseline_mod.build_baseline(protected)
    baseline_mod.save_baseline(base)
    loaded = baseline_mod.load_baseline()
    assert {k: v.sha256 for k, v in loaded.items()} == {k: v.sha256 for k, v in base.items()}


# ---------------------------------------------------------------------- canary
def test_canaries_deploy_and_detect_modification(sandbox):
    _, protected = sandbox
    canaries = canary_mod.deploy_canaries(protected)
    assert len(canaries) == len(config.CANARY_NAMES)

    victim = next(iter(canaries))
    assert canary_mod.canary_touched(victim, canaries) is False  # untouched
    from pathlib import Path

    Path(victim).write_text("encrypted junk", encoding="utf-8")
    assert canary_mod.canary_touched(victim, canaries) is True   # modified


def test_canary_detected_after_locked_rename(sandbox):
    _, protected = sandbox
    canaries = canary_mod.deploy_canaries(protected)
    victim = next(iter(canaries))
    assert canary_mod.canary_touched(victim + ".locked", canaries) is True
    assert canary_mod.is_canary("notes.txt", canaries) is False


# ---------------------------------------------------- end-to-end detection
def _monitor(sandbox):
    _, protected = sandbox
    mon = RansomGuardMonitor(root=protected, logger=EventLogger(echo=False), enforce=False)
    mon.prepare(rebuild=True)
    return mon, protected


def test_encrypting_a_canary_triggers_alert(sandbox):
    mon, protected = _monitor(sandbox)
    from pathlib import Path

    canary = next(iter(mon.canaries))
    Path(canary).write_bytes(os.urandom(4096))        # "encrypt" the decoy
    mon.handle_event("modified", canary)

    assert mon.scorer.score_of(GLOBAL_ACTOR) >= config.W_CANARY
    events = [e["event"] for e in __import__("ransomguard.logger", fromlist=["read_events"]).read_events(config.LOG_FILE)]
    assert "ALERT" in events


def test_encrypting_many_documents_triggers_alert(sandbox):
    mon, protected = _monitor(sandbox)
    pdf = protected / "report.pdf"
    pdf.write_bytes(os.urandom(65536))                # encrypted-in-place pdf
    mon.handle_event("modified", pdf)
    # entropy_jump + magic_broken + low_chi = 60; a second encrypted file crosses 70.
    essay = protected / "documents" / "essay.txt"
    essay.write_bytes(os.urandom(65536))
    mon.handle_event("modified", essay)
    assert mon.scorer.score_of(GLOBAL_ACTOR) >= config.SCORE_THRESHOLD


def test_one_benign_new_jpg_does_not_alert(sandbox):
    # The classic false-positive: a user drops in a fresh photo. High entropy, but magic
    # bytes are intact, no baseline to "jump" from, no canary -> must stay well under 70.
    mon, protected = _monitor(sandbox)
    photo = protected / "holiday.jpg"
    photo.write_bytes(b"\xff\xd8\xff\xe0" + os.urandom(120_000) + b"\xff\xd9")
    mon.handle_event("created", photo)
    assert mon.scorer.score_of(GLOBAL_ACTOR) < config.SCORE_THRESHOLD


def test_backup_folder_events_are_ignored(sandbox):
    mon, protected = _monitor(sandbox)
    config.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    junk = config.BACKUP_DIR / "copy.pdf"
    junk.write_bytes(os.urandom(4096))
    record = mon.handle_event("modified", junk)
    assert record == {}  # ignored, no scoring
