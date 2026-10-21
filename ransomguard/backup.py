"""
backup.py

WHAT: keeps a clean, hash-verified copy of the protected folder in ./sandbox/.backup, plus
      a manifest (manifest.json) recording each file's SHA-256, size, entropy and extension.
      It also refreshes that copy over time for files that have changed in a clearly benign
      way, so the backup tracks legitimate edits without ever snapshotting an attack.

WHY : detection + killing only limits the damage; it does not give the files back. Recovery
      needs a trusted "known-good" version of every file and a way to prove a restored file
      is actually correct - that is what the backup and its SHA-256 manifest provide. We
      take the first snapshot while the folder is known clean (at startup, same moment as
      the baseline), and we NEVER refresh during an active alert, so ransomware output can
      never overwrite a good backup.

The backup lives inside the sandbox and is excluded from the watcher, the simulator and the
baseline scan, so it is never itself treated as user data or attacked.
"""

from __future__ import annotations

import json
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from . import config, entropy
from .baseline import sha256_file


@dataclass(frozen=True)
class ManifestEntry:
    sha256: str
    size: int
    entropy: float
    ext: str

    def as_dict(self) -> dict[str, object]:
        return {"sha256": self.sha256, "size": self.size,
                "entropy": round(self.entropy, 4), "ext": self.ext}


def _rel(path: Path, root: Path) -> str:
    """Relative path (POSIX form) used as the stable manifest key."""
    return path.resolve().relative_to(root.resolve()).as_posix()


def backup_copy_of(relpath: str, backup_dir: Path | None = None) -> Path:
    """Where the clean copy of a given relative path lives inside .backup."""
    backup_dir = backup_dir or config.BACKUP_DIR
    return config.ensure_inside(backup_dir / relpath, config.SANDBOX)


def _scan(path: Path) -> ManifestEntry:
    return ManifestEntry(
        sha256=sha256_file(path),
        size=path.stat().st_size,
        entropy=entropy.file_entropy(path),
        ext=path.suffix.lower(),
    )


def build_backup(
    root: Path | None = None, backup_dir: Path | None = None
) -> dict[str, ManifestEntry]:
    """
    Snapshot the whole protected folder into .backup and write the manifest.

    Called once at startup while the folder is clean. Overwrites any previous backup so a
    fresh run always starts from the current clean state.
    """
    root = config.ensure_inside(root or config.PROTECTED_DIR)
    backup_dir = config.ensure_inside(backup_dir or config.BACKUP_DIR, config.SANDBOX)
    if backup_dir.exists():
        shutil.rmtree(backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, ManifestEntry] = {}
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        relpath = _rel(path, root)
        dest = backup_copy_of(relpath, backup_dir)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)
        manifest[relpath] = _scan(path)

    save_manifest(manifest, backup_dir)
    return manifest


def save_manifest(manifest: dict[str, ManifestEntry], backup_dir: Path | None = None) -> Path:
    backup_dir = backup_dir or config.BACKUP_DIR
    path = config.ensure_inside(backup_dir / config.MANIFEST_FILE.name, config.SANDBOX)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"created": time.time(), "files": {k: v.as_dict() for k, v in manifest.items()}}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def load_manifest(backup_dir: Path | None = None) -> dict[str, ManifestEntry]:
    backup_dir = backup_dir or config.BACKUP_DIR
    path = backup_dir / config.MANIFEST_FILE.name
    if not path.exists():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8")).get("files", {})
    return {
        k: ManifestEntry(v["sha256"], v["size"], v["entropy"], v["ext"]) for k, v in raw.items()
    }


def _looks_clean(path: Path, previous: ManifestEntry | None) -> bool:
    """
    Is this file safe to copy into the backup? We require that it does NOT look like fresh
    ransomware output: its magic bytes must be intact (if it is a known type) and it must
    not have jumped into high-entropy random territory versus its last known entropy.
    """
    try:
        signals = entropy.analyse_file(path)
    except OSError:
        return False
    if signals.magic_ok is False:
        return False
    if previous is not None:
        rise = signals.entropy - previous.entropy
        if rise > config.ENTROPY_JUMP and signals.entropy > config.HIGH_ENTROPY:
            return False
    # A brand-new file that is itself high-entropy AND random-looking is treated as unsafe
    # to back up automatically (it could be dropped ransomware); a real photo still has its
    # magic bytes and so passes the check above.
    if previous is None and signals.looks_random and signals.magic_ok is None:
        return False
    return True


def refresh_clean(
    root: Path | None = None,
    backup_dir: Path | None = None,
    active_alert: bool = False,
) -> int:
    """
    Update the backup for files that changed in a benign way since the last snapshot.

    Returns the number of files refreshed. Does nothing while an alert is active - during
    an attack we must not let encrypted content overwrite good backups.
    """
    if active_alert:
        return 0
    root = config.ensure_inside(root or config.PROTECTED_DIR)
    backup_dir = config.ensure_inside(backup_dir or config.BACKUP_DIR, config.SANDBOX)
    manifest = load_manifest(backup_dir)

    refreshed = 0
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        relpath = _rel(path, root)
        previous = manifest.get(relpath)
        try:
            current_hash = sha256_file(path)
        except OSError:
            continue
        if previous is not None and previous.sha256 == current_hash:
            continue  # unchanged, nothing to do
        if not _looks_clean(path, previous):
            continue  # changed but suspicious: leave the known-good copy in place
        dest = backup_copy_of(relpath, backup_dir)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)
        manifest[relpath] = _scan(path)
        refreshed += 1

    if refreshed:
        save_manifest(manifest, backup_dir)
    return refreshed
