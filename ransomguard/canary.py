"""
canary.py

WHAT: creates a handful of decoy "canary" (honey) files with realistic, valuable-looking
      names, records their hashes, and can tell whether any of them has been modified,
      renamed or deleted.

WHY : a canary is the single strongest signal we have. No legitimate program has any reason
      to touch a file called "aaa_DO_NOT_MODIFY_passwords.txt" - but ransomware that crawls
      a folder encrypting everything will hit it. The names are chosen so an alphabetical
      crawler meets an "aaa_" canary almost first and a "zzz_" canary almost last, so we
      catch the attack early whichever direction it walks. That is why a canary touch is
      weighted +60 in the scorer: on its own it is nearly conclusive.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import config
from .baseline import sha256_file

# Plausible contents so the files look real to anything inspecting them, and so they have
# ordinary low entropy in the baseline (an encrypted canary will stand out even more).
_CANARY_BODY = (
    "CONFIDENTIAL - personal records. Do not edit or move this file.\n"
    "account: 0012-8841-5570\nrecovery: see offline notebook\n"
) * 20


def canary_paths(root: Path | None = None) -> list[Path]:
    """Where the canaries live: some in the root, some in a subfolder, so a crawler that
    only hits top-level files and one that recurses both step on at least one."""
    root = config.ensure_inside(root or config.PROTECTED_DIR)
    names = config.CANARY_NAMES
    paths: list[Path] = []
    for i, name in enumerate(names):
        # Alternate between root and a "documents" subfolder.
        base = root if i % 2 == 0 else root / "documents"
        paths.append(config.ensure_inside(base / name, root))
    return paths


def deploy_canaries(root: Path | None = None) -> dict[str, str]:
    """
    Create the canary files and return {absolute_path: sha256}. Also persisted to
    ./sandbox/canaries.json so the monitor and dashboard agree on which paths are decoys.
    """
    root = config.ensure_inside(root or config.PROTECTED_DIR)
    hashes: dict[str, str] = {}
    for path in canary_paths(root):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_CANARY_BODY, encoding="utf-8")
        hashes[str(path.resolve())] = sha256_file(path)

    config.ensure_inside(config.CANARY_FILE)
    config.CANARY_FILE.write_text(json.dumps(hashes, indent=2), encoding="utf-8")
    return hashes


def load_canaries(path: Path | None = None) -> dict[str, str]:
    """Load the {path: sha256} map written by deploy_canaries()."""
    path = Path(path) if path else config.CANARY_FILE
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def is_canary(path: Path | str, canaries: dict[str, str] | None = None) -> bool:
    """True if `path` is one of our decoys (matched by resolved absolute path or by name).

    We match on name as well as full path because ransomware renames the file (e.g. to
    aaa_...txt.locked); the rename event's source path still carries the canary name.
    """
    canaries = load_canaries() if canaries is None else canaries
    resolved = str(Path(path).resolve())
    if resolved in canaries:
        return True
    name = Path(path).name
    canary_names = {Path(p).name for p in canaries}
    # Strip a ransomware suffix like ".locked" before comparing the name.
    stem = name[: -len(".locked")] if name.endswith(".locked") else name
    return name in canary_names or stem in canary_names


def canary_touched(path: Path | str, canaries: dict[str, str] | None = None) -> bool:
    """
    A canary is "touched" if it is one of ours AND its content no longer matches the
    stored hash, OR it has been deleted/renamed (file missing at its path).

    Any of modify / rename / delete is a strong malicious signal, exactly as required.
    """
    canaries = load_canaries() if canaries is None else canaries
    if not is_canary(path, canaries):
        return False
    resolved = str(Path(path).resolve())
    expected = canaries.get(resolved)
    if expected is None:
        # Matched by name only (e.g. a .locked rename) -> definitely touched.
        return True
    p = Path(path)
    if not p.exists():
        return True                       # deleted or renamed away
    try:
        return sha256_file(p) != expected  # modified in place
    except OSError:
        return True
