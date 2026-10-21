"""
scorer.py

WHAT: turns the raw per-file signals into a single suspicion score for an "actor", and
      decides when that score crosses the action threshold. An actor is whoever we hold
      responsible for an event: in phase 3 there is one global actor ("sandbox"); in
      phase 4 the process monitor gives us real PIDs so each process gets its own score.

WHY : every individual signal lies sometimes. A .zip is high entropy; a backup tool writes
      in bursts; a legitimate "export" might use a new extension. The design principle of
      this project is that ransomware trips SEVERAL signals at once, so we ADD weighted
      points and only act when the total passes a threshold (70). Two further ideas keep
      false positives down:
        * decay - scores halve every 30 s, so ordinary heavy work that trickles a few
          points can never slowly accumulate its way to an alert;
        * the heaviest weight by far is the canary (+60), because that signal almost never
          fires by accident.

This module holds no OS or file logic - it is pure bookkeeping and arithmetic, which makes
it easy to unit-test exactly (see tests/test_scorer.py).
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from . import config
from .baseline import BaselineEntry
from .entropy import FileSignals


@dataclass(frozen=True)
class Reason:
    """One signal that fired, with its point value - kept so we can explain a score."""

    code: str
    points: int
    detail: str = ""


def evaluate_signals(
    current: FileSignals | None,
    baseline: BaselineEntry | None,
    *,
    canary_touched: bool,
    deleted: bool = False,
) -> list[Reason]:
    """
    Decide which per-file signals fire for one event (pure function, no state).

    `current` is the fresh measurement of the file (None if it was deleted/renamed away);
    `baseline` is what the file looked like when clean (None if the file is brand new).
    """
    reasons: list[Reason] = []

    if canary_touched:
        reasons.append(Reason("canary", config.W_CANARY, "decoy file modified/renamed/deleted"))

    # A deleted/renamed-away file we cannot measure; the canary check above still applies.
    if current is None:
        if deleted:
            reasons.append(
                Reason("deleted", config.W_SUSPICIOUS_EXT, "tracked file removed or renamed")
            )
        return reasons

    # Entropy jump: content went from structured to random-looking vs the clean baseline.
    if baseline is not None:
        rise = current.entropy - baseline.entropy
        if rise > config.ENTROPY_JUMP and current.entropy > config.HIGH_ENTROPY:
            reasons.append(
                Reason(
                    "entropy_jump",
                    config.W_ENTROPY_JUMP,
                    f"entropy {baseline.entropy:.2f} -> {current.entropy:.2f}",
                )
            )

    # Magic bytes broken: a known file type no longer has its header (encrypted in place).
    if current.magic_ok is False:
        reasons.append(Reason("magic_broken", config.W_MAGIC_BROKEN, f"{current.ext} header lost"))

    # Low chi-square: the byte distribution is near-uniform, i.e. looks random.
    if current.chi_square <= config.CHI_SQUARE_RANDOM_MAX and current.entropy >= config.HIGH_ENTROPY:
        reasons.append(
            Reason("low_chi_square", config.W_LOW_CHI_SQUARE, f"chi={current.chi_square:.0f}")
        )

    # Suspicious extension: renamed to .locked/.enc/... (a classic ransomware tell).
    if current.ext in config.SUSPICIOUS_EXTS:
        reasons.append(Reason("suspicious_ext", config.W_SUSPICIOUS_EXT, current.ext))

    return reasons


@dataclass
class ActorState:
    """The running score and recent-event history for one actor (PID or 'sandbox')."""

    score: float = 0.0
    last_update: float = field(default_factory=time.monotonic)
    event_times: deque[float] = field(default_factory=deque)  # for burst detection
    reasons: list[Reason] = field(default_factory=list)       # most recent explanation
    alerted: bool = False


class Scorer:
    """
    Accumulates decaying suspicion scores per actor and reports threshold crossings.

    Time is injected (`now`) so tests can drive the clock instead of sleeping; in
    production it defaults to time.monotonic.
    """

    def __init__(
        self,
        threshold: int = config.SCORE_THRESHOLD,
        half_life: float = config.SCORE_HALF_LIFE_SEC,
    ) -> None:
        self.threshold = threshold
        self.half_life = half_life
        self._actors: dict[str, ActorState] = defaultdict(ActorState)

    def _decay(self, state: ActorState, now: float) -> None:
        """Apply exponential decay: score *= 0.5 ** (elapsed / half_life)."""
        elapsed = now - state.last_update
        if elapsed > 0 and state.score > 0:
            state.score *= 0.5 ** (elapsed / self.half_life)
            if state.score < 0.01:
                state.score = 0.0
        state.last_update = now

    def _burst_points(self, state: ActorState, now: float) -> int:
        """Return W_BURST once if the actor made >= BURST_COUNT edits in the window."""
        window_start = now - config.BURST_WINDOW_SEC
        while state.event_times and state.event_times[0] < window_start:
            state.event_times.popleft()
        if len(state.event_times) >= config.BURST_COUNT:
            return config.W_BURST
        return 0

    def observe(
        self, actor: str, reasons: list[Reason], now: float | None = None
    ) -> ActorState:
        """
        Record one event's reasons against `actor`, update the decaying score and burst
        tracking, and return the actor's state (so the caller can read .score/.alerted).
        """
        now = time.monotonic() if now is None else now
        state = self._actors[actor]
        self._decay(state, now)

        state.event_times.append(now)
        points = sum(r.points for r in reasons)

        burst = self._burst_points(state, now)
        all_reasons = list(reasons)
        if burst:
            all_reasons.append(Reason("burst", burst, f"{len(state.event_times)} edits/5s"))
            points += burst

        state.score += points
        state.reasons = all_reasons
        return state

    def should_act(self, actor: str, now: float | None = None) -> bool:
        """True the first time an actor's (decayed) score reaches the threshold."""
        now = time.monotonic() if now is None else now
        state = self._actors[actor]
        self._decay(state, now)
        if state.score >= self.threshold and not state.alerted:
            state.alerted = True
            return True
        return False

    def score_of(self, actor: str, now: float | None = None) -> float:
        now = time.monotonic() if now is None else now
        state = self._actors[actor]
        self._decay(state, now)
        return state.score

    def reset(self, actor: str | None = None) -> None:
        if actor is None:
            self._actors.clear()
        else:
            self._actors.pop(actor, None)
