"""
baseline.py

WHAT: at startup, scans ./sandbox/protected and records, for every file, its Shannon
      entropy, SHA-256 hash, size and extension into ./sandbox/baseline.json.

WHY : detection is about CHANGE. "entropy jumped by > 2.0" only means something if we know
      what the entropy was before the attack. The baseline is that "before" snapshot: the
      scorer compares each live event against it, and recovery (phase 5) uses the hashes to
      tell a clean file from an encrypted one. We take it once, while the folder is known
      to be clean.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from . import config, entropy


@dataclass(frozen=True)
class BaselineEntry:
    entropy: float
    sha256: str
    size: int
    ext: str

    def as_dict(self) -> dict[str, object]:
        return {
            "entropy": round(self.entropy, 4),
            "sha256": self.sha256,
            "size": self.size,
            "ext": self.ext,
        }


def sha256_file(path: Path | str, chunk: int = 1 << 20) -> str:
    """Streaming SHA-256 of a whole file (1 MB chunks, so large files are fine)."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(chunk), b""):
            digest.update(block)
    return digest.hexdigest()


def scan_file(path: Path) -> BaselineEntry:
    """Measure one file for the baseline (full-file hash, sampled entropy)."""
    return BaselineEntry(
        entropy=entropy.file_entropy(path),
        sha256=sha256_file(path),
        size=path.stat().st_size,
        ext=path.suffix.lower(),
    )


def build_baseline(root: Path | None = None) -> dict[str, BaselineEntry]:
    """Scan every file under `root`, skipping the backup folder. Keyed by absolute path."""
    root = config.ensure_inside(root or config.PROTECTED_DIR)
    backup = config.BACKUP_DIR.resolve()
    result: dict[str, BaselineEntry] = {}
    for path in root.rglob("*"):
        if path.is_dir() or backup in path.resolve().parents:
            continue
        try:
            result[str(path.resolve())] = scan_file(path)
        except OSError:
            continue  # file vanished mid-scan; just skip it
    return result


def save_baseline(
    baseline: dict[str, BaselineEntry], path: Path | None = None
) -> Path:
    """Write the baseline to JSON."""
    path = Path(path) if path else config.BASELINE_FILE
    config.ensure_inside(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {key: entry.as_dict() for key, entry in baseline.items()}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def load_baseline(path: Path | None = None) -> dict[str, BaselineEntry]:
    """Read a baseline back from JSON into BaselineEntry objects."""
    path = Path(path) if path else config.BASELINE_FILE
    if not path.exists():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {
        key: BaselineEntry(
            entropy=value["entropy"],
            sha256=value["sha256"],
            size=value["size"],
            ext=value["ext"],
        )
        for key, value in raw.items()
    }
