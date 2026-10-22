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

import hashlib
import json
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

from . import config

# Genesis hash for the first line: there is no previous line to point at.
GENESIS_HASH = "0" * 64


def _line_hash(line: str) -> str:
    """SHA-256 of one serialized log line (without its trailing newline)."""
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


class EventLogger:
    """Append-only JSON-lines logger. Thread-safe because watchdog calls us from its
    own observer thread while the main loop may also log."""

    def __init__(self, path: Path | None = None, echo: bool = True) -> None:
        self.path = Path(path) if path else config.LOG_FILE
        self.echo = echo
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Hash chain: each line carries the SHA-256 of the previous line, so any later edit
        # to an earlier line breaks every hash after it (tamper-evident log). We seed from
        # the existing file so appending across restarts keeps the chain intact.
        self._prev_hash = self._last_hash_on_disk()

    def _last_hash_on_disk(self) -> str:
        if not self.path.exists():
            return GENESIS_HASH
        last = ""
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last = line
        return _line_hash(last) if last else GENESIS_HASH

    def log(self, event: str, **fields: object) -> dict[str, object]:
        """Write one event. Extra keyword args become JSON fields. Returns the record."""
        now = time.time()
        record: dict[str, object] = {
            "ts": round(now, 3),
            "iso": datetime.fromtimestamp(now).isoformat(timespec="seconds"),
            "event": event,
        }
        record.update(fields)

        with self._lock:
            record["prev"] = self._prev_hash  # link to the previous line
            line = json.dumps(record, default=str)
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
            self._prev_hash = _line_hash(line)
            if self.echo:
                print(self._human(record), file=sys.stderr)
        return record

    @staticmethod
    def _human(record: dict[str, object]) -> str:
        """A compact one-line view for the console (the file keeps the full JSON)."""
        extras = " ".join(
            f"{k}={v}" for k, v in record.items() if k not in {"ts", "iso", "event", "prev"}
        )
        return f"[{record['iso']}] {record['event']:<14} {extras}"

    def reset(self) -> None:
        """Truncate the log and restart the hash chain. Used by the evaluation harness."""
        with self._lock:
            self.path.write_text("", encoding="utf-8")
            self._prev_hash = GENESIS_HASH


def verify_log(path: Path | None = None) -> tuple[bool, int]:
    """
    Verify the hash chain of a JSON-lines log.

    Walks the file line by line: each line must carry a `prev` field equal to the SHA-256
    of the line before it (the first points at the genesis hash). Returns (ok, bad_index):
    ok=True means the chain is intact; otherwise bad_index is the 0-based line number where
    the chain first breaks - i.e. the earliest line that was edited, inserted or removed.
    """
    path = Path(path) if path else config.LOG_FILE
    if not path.exists():
        return True, -1
    prev = GENESIS_HASH
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    for i, line in enumerate(lines):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return False, i
        if record.get("prev") != prev:
            return False, i
        prev = _line_hash(line)
    return True, -1


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
