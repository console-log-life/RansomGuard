"""
test_evaluation.py

WHAT: tests the benign workload's safety/canary-skip behaviour and the report's
      table/metric formatting (pure functions, no live trials).

WHY : the live trials in run_experiment are slow and non-deterministic by nature, so we do
      not run them in the unit suite. But the pieces they rely on - "benign work leaves the
      canaries alone" and "the report computes recovery rate / counts correctly" - are
      deterministic and worth pinning, because a wrong metric would quietly corrupt the
      numbers in our report.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ransomguard import canary as canary_mod
from ransomguard import config


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    sb = tmp_path / "sandbox"
    protected = sb / "protected"
    (protected / "documents").mkdir(parents=True)
    monkeypatch.setattr(config, "SANDBOX", sb)
    monkeypatch.setattr(config, "PROTECTED_DIR", protected)
    monkeypatch.setattr(config, "CANARY_FILE", sb / "canaries.json")
    (protected / "notes.txt").write_text("real document", encoding="utf-8")
    (protected / "documents" / "essay.txt").write_text("another real one", encoding="utf-8")
    return sb, protected


def test_benign_workload_skips_canaries(sandbox):
    from tools import benign_workload

    _, protected = sandbox
    canaries = canary_mod.deploy_canaries(protected)
    before = {c: Path(c).read_bytes() for c in canaries}

    benign_workload.edit_text_files(protected, rounds=2)

    # Every canary must be byte-identical afterwards: benign work never touches a decoy.
    for c, data in before.items():
        assert Path(c).read_bytes() == data
    # But the real documents WERE edited.
    assert "edited at" in (protected / "notes.txt").read_text(encoding="utf-8")


def test_benign_workload_refuses_outside_sandbox(tmp_path, capsys):
    from tools import benign_workload

    outside = tmp_path / "home"
    outside.mkdir()
    rc = benign_workload.main(["--path", str(outside)])
    assert rc == 2
    assert "REFUSED" in capsys.readouterr().out


def test_report_table_and_metrics():
    from evaluation import report

    base = {"files_failed": 0, "recovery_rate": 1.0, "false_positives": 0, "wrongful_kills": 0}
    results = [
        {"kind": "attack", "label": "a", "order": "alphabetical", "delay": 0.2,
         "files_total": 16, "detection_time_s": 2.5, "attributed": True, "killed": True,
         "files_encrypted": 10, "files_restored": 10, "final_recovered": 16,
         "final_clean": True, "leftover_locked": 0, **base},
        {"kind": "attack", "label": "b", "order": "random", "delay": 0.1,
         "files_total": 16, "detection_time_s": None, "attributed": False, "killed": False,
         "files_encrypted": 16, "files_restored": 16, "final_recovered": 16,
         "final_clean": True, "leftover_locked": 0, **base},
        {"kind": "benign", "label": "benign-1", "order": "", "delay": 0.0,
         "files_total": 16, "detection_time_s": None, "attributed": False, "killed": False,
         "files_encrypted": 0, "files_restored": 0, "final_recovered": 16,
         "final_clean": True, "leftover_locked": 0, **base},
    ]
    table = report.build_table(results)
    assert "Attack trials" in table
    assert "Benign trials" in table
    assert "folder fully clean at end (ground truth): 2/2 trials" in table
    assert "0 false positives" in table
    # the unattributed trial renders detection time as a dash, not a crash
    assert "| 2 | random | 0.1s | 16 | - | no | no | 16 | 16/16 | yes |" in table
