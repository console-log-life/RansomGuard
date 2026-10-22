"""
test_dashboard.py

WHAT: tests the dashboard's pure view logic (dashboard/view.py) against a fixture event log
      that contains TWO runs in one file, a kill + multiple recovery sweeps, and repeated
      canary events for the same decoy.

WHY : the live demo showed the dashboard was misleading after an attack - it mixed a
      previous run into the chart, summed only the last recovery, double-counted a canary
      hit twice, and stayed "UNDER ATTACK" forever. These tests pin the corrected behaviour:
      scope to the current run, decay the score to now, sum recovery over the run, count
      unique canaries, and flip to "stopped" once the attacker is killed and files restored.
"""

from __future__ import annotations

from dashboard import view
from ransomguard import config


def _fixture_events() -> list[dict]:
    """Two runs in one log. Run 1 is an old, fully-handled attack; run 2 is the current one."""
    return [
        # ---- run 1 (previous demo, should be ignored by the dashboard) ----
        {"event": "startup", "ts": 100.0, "canaries": 4, "enforce": True, "path": "/sb"},
        {"event": "fs_event", "ts": 101.0, "canary": True, "path": "aaa_passwords.txt", "score": 60.0},
        {"event": "ALERT", "ts": 101.0, "score": 85.0},
        {"event": "response_done", "ts": 102.0, "killed": True, "pid": 111},
        {"event": "recovery", "ts": 102.5, "affected": 9, "restored": 9},
        # ---- run 2 (current run) ----
        {"event": "startup", "ts": 200.0, "canaries": 4, "enforce": True, "path": "/sb"},
        {"event": "fs_event", "ts": 201.0, "canary": True, "path": "aaa_passwords.txt", "score": 60.0},
        {"event": "fs_event", "ts": 201.2, "canary": True, "path": "aaa_passwords.txt.locked", "score": 85.0},
        {"event": "ALERT", "ts": 201.2, "score": 85.0},
        {"event": "fs_event", "ts": 201.5, "canary": True, "path": "documents/zzz_wallet_notes.txt", "score": 120.0},
        {"event": "culprit", "ts": 202.0, "pid": 9004, "name": "python.exe", "write_rate": 50000},
        {"event": "response_done", "ts": 202.5, "killed": True, "pid": 9004, "name": "python.exe"},
        {"event": "recovery", "ts": 202.6, "affected": 3, "restored": 3},
        {"event": "recovery", "ts": 203.0, "affected": 2, "restored": 2},   # second sweep
    ]


def test_current_run_ignores_previous_runs():
    run = view.current_run(_fixture_events())
    assert run[0]["event"] == "startup" and run[0]["ts"] == 200.0
    assert all(e["ts"] >= 200.0 for e in run)
    # the old run-1 recovery (affected 9) must not leak in
    assert not any(e.get("affected") == 9 for e in run)


def test_recovery_totals_sum_over_the_run():
    run = view.current_run(_fixture_events())
    affected, restored = view.recovery_totals(run)
    assert (affected, restored) == (5, 5)   # 3 + 2, not just the last sweep


def test_unique_canaries_counted_and_clamped():
    run = view.current_run(_fixture_events())
    # The same canary appears three times (incl. a .locked rename) + one other -> 2 unique.
    assert view.canaries_touched(run) == {"aaa_passwords.txt", "zzz_wallet_notes.txt"}
    touched, intact = view.canary_status(run, total=4)
    assert (touched, intact) == (2, 2)


def test_canary_status_is_clamped_to_total():
    events = [{"event": "fs_event", "canary": True, "path": f"c{i}.txt"} for i in range(9)]
    touched, intact = view.canary_status(events, total=4)
    assert touched == 4 and intact == 0   # never negative, never above total


def test_status_flips_to_stopped_after_kill_and_recovery():
    run = view.current_run(_fixture_events())
    assert view.run_status(run) == "stopped"


def test_status_is_under_attack_before_any_kill_or_recovery():
    events = [
        {"event": "startup", "ts": 1.0, "canaries": 4},
        {"event": "fs_event", "ts": 1.1, "score": 85.0, "canary": True, "path": "aaa.txt"},
        {"event": "ALERT", "ts": 1.1, "score": 85.0},
    ]
    assert view.run_status(events) == "attack"


def test_status_clean_without_alert():
    events = [{"event": "startup", "ts": 1.0}, {"event": "fs_event", "ts": 1.1, "score": 10.0}]
    assert view.run_status(events) == "clean"


def test_score_decays_to_now():
    events = [{"event": "fs_event", "ts": 1000.0, "score": 80.0}]
    # Right away: full score. After one half-life: halved. After two: quartered.
    assert view.decayed_score(events, now=1000.0, half_life=30.0) == 80.0
    assert view.decayed_score(events, now=1030.0, half_life=30.0) == 40.0
    assert view.decayed_score(events, now=1060.0, half_life=30.0) == 20.0


def test_score_uses_default_half_life_from_config():
    events = [{"event": "fs_event", "ts": 0.0, "score": 100.0}]
    expected = round(100.0 * 0.5 ** (config.SCORE_HALF_LIFE_SEC / config.SCORE_HALF_LIFE_SEC), 1)
    assert view.decayed_score(events, now=config.SCORE_HALF_LIFE_SEC) == expected  # == 50.0
