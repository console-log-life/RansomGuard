"""
logger.py

WHAT: a tiny structured logger that appends one JSON object per line (JSON Lines) to
      ./sandbox/events.jsonl, and also prints a short human line to the console.

WHY : every other part of the project - the live dashboard (phase 7) and especially the
      evaluation (phase 6) - needs a machine-readable record of what happened and WHEN.
      Free-text logs are impossible to compute metrics from. JSON Lines is the simplest
      format that is both appendable in real time and trivially parsed later with one
      json.loads() per line.

Each record always carries: ts (epoch seconds), iso (human time), event (a short type
string) and whatever keyword fields the caller passes (path, score, pid, reason, ...).
"""

from __future__ import annotations

import json
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

from . import config


class EventLogger:
    """Append-only JSON-lines logger. Thread-safe because watchdog calls us from its
    own observer thread while the main loop may also log."""

    def __init__(self, path: Path | None = None, echo: bool = True) -> None:
        self.path = Path(path) if path else config.LOG_FILE
        self.echo = echo
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: str, **fields: object) -> dict[str, object]:
        """Write one event. Extra keyword args become JSON fields. Returns the record."""
        now = time.time()
        record: dict[str, object] = {
            "ts": round(now, 3),
            "iso": datetime.fromtimestamp(now).isoformat(timespec="seconds"),
            "event": event,
        }
        record.update(fields)

        line = json.dumps(record, default=str)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
            if self.echo:
                print(self._human(record), file=sys.stderr)
        return record

    @staticmethod
    def _human(record: dict[str, object]) -> str:
        """A compact one-line view for the console (the file keeps the full JSON)."""
        extras = " ".join(
            f"{k}={v}" for k, v in record.items() if k not in {"ts", "iso", "event"}
        )
        return f"[{record['iso']}] {record['event']:<14} {extras}"

    def reset(self) -> None:
        """Truncate the log. Used by the evaluation harness between trials."""
        with self._lock:
            self.path.write_text("", encoding="utf-8")


def read_events(path: Path | None = None) -> list[dict[str, object]]:
    """Load every event record from a JSON-lines log (used by evaluation/dashboard)."""
    path = Path(path) if path else config.LOG_FILE
    if not path.exists():
        return []
    events: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            events.append(json.loads(line))
    return events
