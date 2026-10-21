"""
fake_ransomware.py

WHAT: a SAFE, fully reversible stand-in for ransomware. It walks ./sandbox/protected,
      AES-256-GCM encrypts each file in place, renames it to <name>.locked and deletes
      the original. It is the "attacker" that the detector (phases 3-4) must notice and
      stop, and that recovery (phase 5) must undo.

WHY : we cannot test a ransomware detector without ransomware-like behaviour. Running real
      malware would be reckless and unethical, so this script mimics only the one thing
      that matters cryptographically - turning readable files into high-entropy ciphertext
      at speed - and nothing else that makes real ransomware dangerous.

HARD SAFETY LIMITS (enforced in code, not just promised):
  * Refuses to start unless the resolved target is inside ./sandbox. See _guard_target().
  * Never leaves the sandbox: every read/write/delete goes through config.ensure_inside().
  * Always writes its AES key to ./sandbox/sim_key.bin BEFORE touching any file, so undo.py
    (or recovery) can decrypt everything. No key = no run.
  * Never deletes the backup folder, the key file, canary bookkeeping or anything outside
    the sandbox; skips .backup and .locked files and the sandbox metadata files entirely.
  * Does not spread, persist, hide, elevate, change system settings, or use the network.
    It is a single short-lived process that prints its own PID and exits.

Run:  python -m simulator.fake_ransomware                 # default, slow enough to watch
      python -m simulator.fake_ransomware --delay 0.05 --count 20 --order random
      python -m simulator.fake_ransomware --dry-run       # list targets, encrypt nothing
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Allow "python simulator/fake_ransomware.py" as well as "-m simulator.fake_ransomware".
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ransomguard import config  # noqa: E402

LOCKED_SUFFIX = ".locked"
NONCE_SIZE = 12  # 96-bit nonce is the standard size for AES-GCM

# Files the simulator must never encrypt, even inside the sandbox: our own metadata and
# anything already encrypted. (The .backup folder is excluded by skipping the dir below.)
SKIP_NAMES = {
    config.SIM_KEY_FILE.name,
    config.BASELINE_FILE.name,
    config.CANARY_FILE.name,
    config.LOG_FILE.name,
}


def _guard_target(raw: str) -> Path:
    """Resolve the target folder and refuse anything outside ./sandbox.

    This is the gate the whole safety story rests on: if the path is not inside the
    sandbox we exit non-zero before generating a key or opening a single file.
    """
    target = Path(raw).resolve()
    config.ensure_inside(target)                 # raises SandboxViolation if outside
    if not target.exists() or not target.is_dir():
        raise NotADirectoryError(f"target folder does not exist: {target}")
    return target


def _collect_targets(root: Path, order: str) -> list[Path]:
    """List the files to encrypt, skipping backups, our metadata and already-locked files."""
    files: list[Path] = []
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        # Never descend into the clean backup copy.
        if config.BACKUP_DIR.resolve() in path.resolve().parents:
            continue
        if path.name in SKIP_NAMES or path.suffix == LOCKED_SUFFIX:
            continue
        files.append(path)

    if order == "alphabetical":
        files.sort(key=lambda p: str(p).lower())
    elif order == "random":
        random.shuffle(files)
    # "asis" leaves filesystem order untouched.
    return files


def _encrypt_file(path: Path, key: bytes) -> Path:
    """
    Encrypt one file in place: write <name>.locked, then delete the original.

    On-disk format matches demo_entropy.py and undo.py:
        [12-byte nonce][ciphertext + 16-byte GCM tag]
    The original filename is stored as GCM associated data so undo can restore the exact
    name and so the tag also authenticates it.
    """
    config.ensure_inside(path)                   # defence in depth: never act outside sandbox
    plaintext = path.read_bytes()
    nonce = os.urandom(NONCE_SIZE)
    original_name = path.name.encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, original_name)

    locked = config.ensure_inside(path.with_name(path.name + LOCKED_SUFFIX))
    # Length-prefix the original name so undo can split header from ciphertext.
    header = len(original_name).to_bytes(2, "big") + original_name
    locked.write_bytes(header + nonce + ciphertext)
    path.unlink()                                # delete original (inside sandbox only)
    return locked


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Safe, reversible ransomware simulator.")
    parser.add_argument(
        "--path", default=str(config.PROTECTED_DIR), help="folder to attack (must be in ./sandbox)"
    )
    parser.add_argument("--delay", type=float, default=0.15, help="seconds to wait between files")
    parser.add_argument("--count", type=int, default=0, help="max files to encrypt (0 = all)")
    parser.add_argument(
        "--order",
        choices=("alphabetical", "random", "asis"),
        default="alphabetical",
        help="traversal order (alphabetical hits the aaa_/zzz_ canaries early/late)",
    )
    parser.add_argument("--seed", type=int, default=None, help="seed for --order random")
    parser.add_argument(
        "--dry-run", action="store_true", help="list targets and exit without encrypting"
    )
    args = parser.parse_args(argv)

    # Gate 1: the target must be inside the sandbox, or we never start.
    try:
        root = _guard_target(args.path)
    except (config.SandboxViolation, NotADirectoryError) as exc:
        print(f"REFUSED: {exc}")
        return 2

    if args.seed is not None:
        random.seed(args.seed)

    targets = _collect_targets(root, args.order)
    if args.count > 0:
        targets = targets[: args.count]

    pid = os.getpid()
    print(f"[simulator] PID={pid} target={root}")
    print(f"[simulator] {len(targets)} files, order={args.order}, delay={args.delay}s")

    if args.dry_run:
        for path in targets:
            print(f"  would encrypt: {path.relative_to(root)}")
        print("[simulator] dry run - nothing was changed")
        return 0

    # Gate 2: generate the key and PERSIST it before encrypting anything. If we cannot
    # save the key, we refuse to proceed - an unrecoverable run is not allowed.
    key = AESGCM.generate_key(bit_length=256)
    config.ensure_inside(config.SIM_KEY_FILE)
    config.SIM_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    config.SIM_KEY_FILE.write_bytes(key)
    print(f"[simulator] AES-256 key saved to {config.SIM_KEY_FILE} (undo needs this)")

    start = time.perf_counter()
    encrypted = 0
    for path in targets:
        try:
            locked = _encrypt_file(path, key)
        except (OSError, config.SandboxViolation) as exc:
            # A file may already be gone (the detector could be deleting/restoring it);
            # skip it rather than crash, so the simulator stays realistic and robust.
            print(f"  skip {path.name}: {exc}")
            continue
        encrypted += 1
        print(f"  locked {locked.relative_to(root)}")
        if args.delay > 0:
            time.sleep(args.delay)

    elapsed = time.perf_counter() - start
    print(f"[simulator] done: encrypted {encrypted}/{len(targets)} files in {elapsed:.2f}s")
    print(f"[simulator] undo with: python -m simulator.undo")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
