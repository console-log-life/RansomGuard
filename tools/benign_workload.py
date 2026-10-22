"""
benign_workload.py

WHAT: performs normal, non-malicious file activity inside ./sandbox/protected - editing
      text files, copying photos, creating a zip, writing a large compressed archive.

WHY : a detector is only useful if it does NOT cry wolf. This script is the false-positive
      test: it does the kind of heavy, bursty, even high-entropy work a real user does
      (saving a big .zip is high entropy, just like ciphertext), and the monitor should
      sail through it with ZERO alerts. The evaluation runs this under the enforcing
      monitor and counts how many false alerts (and wrongful kills) occur - the target is 0.

Every path is sandbox-guarded, exactly like the simulator, so this too can only ever touch
./sandbox.

Run:  python tools/benign_workload.py
      python tools/benign_workload.py --rounds 3
"""

from __future__ import annotations

import argparse
import gzip
import os
import shutil
import sys
import time
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ransomguard import canary as canary_mod  # noqa: E402
from ransomguard import config  # noqa: E402


def edit_text_files(root: Path, rounds: int) -> int:
    """Append a line to each real .txt document a few times - ordinary editing.

    Canary/decoy files are deliberately skipped: they have obvious "do-not-touch" names
    (aaa_DO_NOT_MODIFY_passwords.txt, ...) that no normal workflow edits. Touching one is
    exactly the malicious signal we want, so a fair false-positive test must leave them
    alone - just as a real user would.
    """
    touched = 0
    canaries = canary_mod.load_canaries()
    texts = [p for p in root.rglob("*.txt") if not canary_mod.is_canary(p, canaries)]
    for _ in range(rounds):
        for path in texts:
            config.ensure_inside(path)
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(f"\n# edited at {time.strftime('%H:%M:%S')} - notes appended\n")
            touched += 1
            time.sleep(0.05)
    return touched


def copy_photos(root: Path) -> int:
    """Duplicate images, as if importing/organising a photo folder (high entropy, benign)."""
    copied = 0
    media = root / "media"
    media.mkdir(exist_ok=True)
    for src in list(root.rglob("*.jpg")) + list(root.rglob("*.png")):
        dest = config.ensure_inside(media / f"copy_{src.stem}{src.suffix}")
        shutil.copy2(src, dest)
        copied += 1
        time.sleep(0.05)
    return copied


def make_zip(root: Path) -> int:
    """Zip up the documents folder - a normal 'archive my work' action."""
    docs = root / "documents"
    if not docs.is_dir():
        return 0
    target = config.ensure_inside(root / "archives" / "documents_backup.zip")
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in docs.rglob("*"):
            if path.is_file():
                zf.write(path, path.relative_to(root))
    return 1


def write_large_compressed(root: Path, size: int = 2_000_000) -> int:
    """
    Save a big gzip file. This is the deliberately tricky case: compressed data has high
    entropy (~8.0), just like encryption - but it keeps its gzip magic bytes, is a brand
    new file (no baseline to 'jump' from) and has a normal extension, so a well-designed
    detector must NOT flag it.
    """
    target = config.ensure_inside(root / "archives" / "dataset.csv.gz")
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = ("timestamp,sensor,value\n" + "".join(
        f"{i},sensor_{i % 8},{(i * 37) % 1000}\n" for i in range(size // 24)
    )).encode()
    with gzip.open(target, "wb") as handle:
        handle.write(payload)
    return 1


def run(root: Path | None = None, rounds: int = 2) -> dict[str, int]:
    root = config.ensure_inside(root or config.PROTECTED_DIR)
    print(f"[benign] PID={os.getpid()} working in {root}")
    stats = {
        "text_edits": edit_text_files(root, rounds),
        "photos_copied": copy_photos(root),
        "zips_created": make_zip(root),
        "compressed_files": write_large_compressed(root),
    }
    print(f"[benign] done: {stats}")
    return stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Benign file activity for false-positive tests.")
    parser.add_argument("--path", default=str(config.PROTECTED_DIR))
    parser.add_argument("--rounds", type=int, default=2, help="how many times to edit each text file")
    args = parser.parse_args(argv)
    try:
        root = config.ensure_inside(Path(args.path))
    except config.SandboxViolation as exc:
        print(f"REFUSED: {exc}")
        return 2
    run(root, args.rounds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
