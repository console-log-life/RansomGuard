"""
undo.py

WHAT: reverses the simulator. It reads the AES key from ./sandbox/sim_key.bin, finds every
      *.locked file in ./sandbox/protected, decrypts it, restores the original filename and
      deletes the .locked copy.

WHY : the simulator must always be undoable without the detector - this is our safety net
      for the demo. If a run goes wrong, or we just want the corpus back, `python -m
      simulator.undo` returns everything to plaintext using the saved key. It verifies the
      GCM tag on every file, so a decrypt either succeeds exactly or is reported as failed;
      it never writes garbage.

This is intentionally separate from recovery.py (phase 5): undo trusts the saved key and
is for US; recovery restores from the hash-verified backup and is what the tool does to a
victim in a real detection, where no key is available.

Run:  python -m simulator.undo
      python -m simulator.undo --key ./sandbox/sim_key.bin --path ./sandbox/protected
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ransomguard import config  # noqa: E402
from simulator.fake_ransomware import LOCKED_SUFFIX, NONCE_SIZE  # noqa: E402


def _decrypt_file(locked: Path, key: bytes) -> Path:
    """
    Decrypt one .locked file and restore its original name.

    Reverses the layout written by fake_ransomware._encrypt_file:
        [2-byte name length][original name][12-byte nonce][ciphertext + GCM tag]
    The original name is the GCM associated data, so a wrong key or a tampered file
    raises InvalidTag instead of producing wrong plaintext.
    """
    config.ensure_inside(locked)
    blob = locked.read_bytes()
    name_len = int.from_bytes(blob[:2], "big")
    original_name = blob[2 : 2 + name_len]
    rest = blob[2 + name_len :]
    nonce, ciphertext = rest[:NONCE_SIZE], rest[NONCE_SIZE:]

    plaintext = AESGCM(key).decrypt(nonce, ciphertext, original_name)

    target = config.ensure_inside(locked.with_name(original_name.decode("utf-8")))
    target.write_bytes(plaintext)
    locked.unlink()
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Decrypt everything the simulator locked.")
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
    locked_files = sorted(root.rglob(f"*{LOCKED_SUFFIX}"))
    if not locked_files:
        print(f"nothing to undo: no *{LOCKED_SUFFIX} files under {root}")
        return 0

    restored = failed = 0
    for locked in locked_files:
        try:
            target = _decrypt_file(locked, key)
        except (InvalidTag, OSError, ValueError) as exc:
            print(f"  FAILED {locked.name}: {exc}")
            failed += 1
            continue
        restored += 1
        print(f"  restored {target.relative_to(root)}")

    print(f"[undo] restored {restored} files, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
