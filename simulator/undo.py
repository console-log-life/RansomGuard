"""
undo.py

WHAT: reverses the simulator for every attack mode. It reads the AES key from
      ./sandbox/sim_key.bin, scans ./sandbox/protected for files that are RansomGuard-sim
      containers (identified by their magic header, so both renamed `.locked` files and
      in-place-encrypted files are found), rebuilds each original and restores its name.

WHY : the simulator must always be undoable without the detector - our safety net for the
      demo. Because every mode (full, intermittent, no-rename, base64) writes the same
      self-describing container, one routine reverses them all. Each encrypted chunk is
      GCM-verified during rebuild, so an undo either reproduces the original exactly or
      fails loudly; it never writes garbage.

Run:  python -m simulator.undo
      python -m simulator.undo --key ./sandbox/sim_key.bin --path ./sandbox/protected
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ransomguard import config  # noqa: E402
from simulator import container  # noqa: E402
from simulator.fake_ransomware import LOCKED_SUFFIX  # noqa: E402


def _restore_file(path: Path, key: bytes) -> Path:
    """Rebuild one container file to its original name and remove the encrypted copy."""
    config.ensure_inside(path)
    blob = path.read_bytes()
    original_name, plaintext = container.rebuild(blob, key)
    target = config.ensure_inside(path.with_name(original_name))
    target.write_bytes(plaintext)
    if path.resolve() != target.resolve():
        path.unlink()  # a renamed (.locked) copy; in-place files were just overwritten back
    return target


def _find_containers(root: Path) -> list[Path]:
    """Every file under root whose bytes start with the sim container magic."""
    found: list[Path] = []
    for path in sorted(root.rglob("*")):
        if path.is_dir() or config.BACKUP_DIR.resolve() in path.resolve().parents:
            continue
        try:
            if container.is_container(path.read_bytes()[: len(container.MAGIC)]):
                found.append(path)
        except OSError:
            continue
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Decrypt everything the simulator encrypted.")
    parser.add_argument("--key", default=str(config.SIM_KEY_FILE), help="path to the saved AES key")
    parser.add_argument("--path", default=str(config.PROTECTED_DIR), help="folder to undo")
    args = parser.parse_args(argv)

    try:
        root = config.ensure_inside(Path(args.path))
        key_path = config.ensure_inside(Path(args.key))
    except config.SandboxViolation as exc:
        print(f"REFUSED: {exc}")
        return 2

    if not key_path.exists():
        print(f"no key at {key_path} - cannot undo (was the simulator ever run?)")
        return 1

    key = key_path.read_bytes()
    targets = _find_containers(root)
    if not targets:
        print(f"nothing to undo: no sim-encrypted files under {root}")
        return 0

    restored = failed = 0
    for path in targets:
        try:
            target = _restore_file(path, key)
        except (InvalidTag, OSError, ValueError) as exc:
            print(f"  FAILED {path.name}: {exc}")
            failed += 1
            continue
        restored += 1
        print(f"  restored {target.relative_to(root)}")

    print(f"[undo] restored {restored} files, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
