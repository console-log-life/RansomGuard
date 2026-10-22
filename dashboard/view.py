"""
view.py

WHAT: the pure (streamlit-free) logic behind the dashboard - slicing the event log to the
      current run, computing the decayed score, summing recovery across the run, counting
      canaries touched, and deciding the status banner.

WHY : the dashboard was misleading after an attack - it showed stale, whole-file numbers and
      stayed "UNDER ATTACK" forever. Putting the logic here (not inside app.py, which runs
      streamlit on import) lets us unit-test it against a fixture log, so the demo view is
      correct and provably so.
"""

from __future__ import annotations

from pathlib import Path

from ransomguard import config


def current_run(events: list[dict]) -> list[dict]:
    """Return only the events from the latest run: everything after the last 'startup'."""
    last_start = None
    for i, e in enumerate(events):
        if e.get("event") == "startup":
            last_start = i
    return events[last_start:] if last_start is not None else list(events)


def decayed_score(events: list[dict], now: float, half_life: float | None = None) -> float:
    """
    The suspicion score decayed to `now`, matching scorer.py's half-life.

    The log stores the score at the moment each event was written; after the attack stops no
    new events arrive, so the displayed score must keep decaying on its own - otherwise it
    would sit frozen at its peak. We take the most recent scored event and apply
    score * 0.5 ** (elapsed / half_life).
    """
    half_life = config.SCORE_HALF_LIFE_SEC if half_life is None else half_life
    scored = [e for e in events if isinstance(e.get("score"), (int, float))]
    if not scored:
        return 0.0
    last = max(scored, key=lambda e: e.get("ts", 0))
    elapsed = max(0.0, now - float(last.get("ts", now)))
    return round(float(last["score"]) * (0.5 ** (elapsed / half_life)), 1)


def recovery_totals(events: list[dict]) -> tuple[int, int]:
    """Sum (affected, restored) over ALL recovery events in the run, not just the last."""
    recs = [e for e in events if e.get("event") == "recovery"]
    affected = sum(int(e.get("affected", 0)) for e in recs)
    restored = sum(int(e.get("restored", 0)) for e in recs)
    return affected, restored


def _canary_stem(path: str) -> str:
    """The canary's real name, stripping a trailing ransomware suffix like '.locked'."""
    name = Path(path).name
    for suffix in config.SUSPICIOUS_EXTS:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def canaries_touched(events: list[dict]) -> set[str]:
    """Unique canary files touched in the run (deduped by real name, ignoring .locked)."""
    touched: set[str] = set()
    for e in events:
        if e.get("event") == "fs_event" and e.get("canary"):
            path = e.get("path")
            if path:
                touched.add(_canary_stem(str(path)))
    return touched


def canary_status(events: list[dict], total: int) -> tuple[int, int]:
    """(touched, intact), both clamped to [0, total]."""
    touched = min(len(canaries_touched(events)), max(0, total))
    intact = max(0, total - touched)
    return touched, intact


def run_status(events: list[dict]) -> str:
    """One of: 'clean', 'attack' (alert, not yet stopped), 'stopped' (killed and/or recovered)."""
    if not any(e.get("event") == "ALERT" for e in events):
        return "clean"
    killed = any(e.get("event") == "response_done" and e.get("killed") for e in events)
    recovered = any(e.get("event") == "recovery" for e in events)
    return "stopped" if (killed or recovered) else "attack"


def canary_total(events: list[dict]) -> int:
    """How many canaries this run deployed (from the startup record; fall back to config)."""
    for e in events:
        if e.get("event") == "startup" and isinstance(e.get("canaries"), int):
            return e["canaries"]
    return len(config.CANARY_NAMES)
