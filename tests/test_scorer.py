"""
test_scorer.py

WHAT: tests the scoring arithmetic - which signals fire, how points add up, the decay, the
      burst rule and the single-shot threshold crossing.

WHY : the scorer is the project's "brain". Its numbers decide whether a process is killed,
      so they must be exactly as documented in config.py. Because time is injected into the
      scorer, we drive a fake clock here instead of sleeping - fast and deterministic.
"""

from __future__ import annotations

from pathlib import Path

from ransomguard import config
from ransomguard.baseline import BaselineEntry
from ransomguard.entropy import FileSignals
from ransomguard.scorer import Reason, Scorer, evaluate_signals


def _signals(entropy_val, chi, magic_ok, ext=".pdf"):
    return FileSignals(
        path=Path("x" + ext),
        size=65536,
        ext=ext,
        entropy=entropy_val,
        chi_square=chi,
        magic_ok=magic_ok,
        looks_random=(entropy_val >= config.HIGH_ENTROPY and chi <= config.CHI_SQUARE_RANDOM_MAX),
    )


# ------------------------------------------------------------ evaluate_signals
def test_encrypted_pdf_trips_three_signals():
    base = BaselineEntry(entropy=4.2, sha256="x", size=65536, ext=".pdf")
    current = _signals(7.98, 240, magic_ok=False)
    codes = {r.code for r in evaluate_signals(current, base, canary_touched=False)}
    assert codes == {"entropy_jump", "magic_broken", "low_chi_square"}


def test_compressed_file_does_not_trip_entropy_jump_without_baseline_gap():
    # A jpg that was ALREADY high entropy in the baseline must not look like a jump.
    base = BaselineEntry(entropy=7.97, sha256="x", size=1000, ext=".jpg")
    current = _signals(7.98, 240, magic_ok=True, ext=".jpg")
    codes = {r.code for r in evaluate_signals(current, base, canary_touched=False)}
    assert "entropy_jump" not in codes  # rise is ~0, not > 2.0


def test_canary_touch_alone_is_sixty_points():
    reasons = evaluate_signals(None, None, canary_touched=True, deleted=True)
    assert any(r.code == "canary" and r.points == config.W_CANARY for r in reasons)


def test_suspicious_extension_fires():
    current = _signals(7.9, 230, magic_ok=None, ext=".locked")
    codes = {r.code for r in evaluate_signals(current, None, canary_touched=False)}
    assert "suspicious_ext" in codes


def test_new_file_with_no_baseline_has_no_entropy_jump():
    current = _signals(7.9, 230, magic_ok=None, ext=".txt")
    codes = {r.code for r in evaluate_signals(current, None, canary_touched=False)}
    assert "entropy_jump" not in codes


# ---------------------------------------------------------------- accumulation
def test_score_accumulates_and_crosses_threshold():
    scorer = Scorer()
    t = 1000.0
    # entropy_jump(30) + magic_broken(20) + low_chi(10) = 60, below 70.
    reasons = [Reason("entropy_jump", 30), Reason("magic_broken", 20), Reason("low_chi_square", 10)]
    scorer.observe("pid1", reasons, now=t)
    assert not scorer.should_act("pid1", now=t)
    assert scorer.score_of("pid1", now=t) == 60

    # A second similar file pushes us well past 70.
    scorer.observe("pid1", reasons, now=t + 1)
    assert scorer.should_act("pid1", now=t + 1)


def test_should_act_fires_only_once():
    scorer = Scorer()
    scorer.observe("pid1", [Reason("canary", 60), Reason("magic_broken", 20)], now=0.0)
    assert scorer.should_act("pid1", now=0.0) is True
    assert scorer.should_act("pid1", now=0.0) is False  # already alerted


def test_scores_decay_by_half_every_half_life():
    scorer = Scorer(half_life=30.0)
    scorer.observe("pid1", [Reason("entropy_jump", 40)], now=0.0)
    assert scorer.score_of("pid1", now=0.0) == 40
    # After exactly one half-life, 40 -> 20.
    assert scorer.score_of("pid1", now=30.0) == 40 * 0.5
    # After two half-lives, 40 -> 10.
    assert round(scorer.score_of("pid1", now=60.0), 3) == 10.0


def test_decay_prevents_slow_accumulation_from_normal_work():
    # Ten small +10 events spread one half-life apart must never reach 70.
    scorer = Scorer(half_life=30.0)
    peak = 0.0
    for i in range(10):
        scorer.observe("pid1", [Reason("low_chi_square", 10)], now=i * 30.0)
        peak = max(peak, scorer.score_of("pid1", now=i * 30.0))
    assert peak < config.SCORE_THRESHOLD


def test_burst_adds_points_after_many_rapid_events():
    scorer = Scorer()
    # BURST_COUNT rapid tiny events inside the window trigger the burst bonus.
    for i in range(config.BURST_COUNT):
        state = scorer.observe("pid1", [], now=1000.0 + i * 0.1)
    assert any(r.code == "burst" for r in state.reasons)


def test_actors_are_scored_independently():
    scorer = Scorer()
    scorer.observe("pidA", [Reason("canary", 60)], now=0.0)
    scorer.observe("pidB", [Reason("low_chi_square", 10)], now=0.0)
    assert scorer.score_of("pidA", now=0.0) == 60
    assert scorer.score_of("pidB", now=0.0) == 10
