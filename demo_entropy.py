"""
demo_entropy.py

WHAT: a 5-second demo of the core measurement idea. It prints Shannon entropy, the
      chi-square statistic and the magic-byte check for four files:
        1. a plain text file        (structured, low entropy)
        2. a JPEG                   (already compressed, high entropy - the hard case)
        3. a ZIP archive            (also compressed, high entropy)
        4. an AES-256-GCM encrypted copy of file 1  (what ransomware produces)

WHY : this is the slide to show first. It makes two points at once:
        * encryption pushes entropy to ~8.0 and chi-square down to ~255, and destroys
          the file header - so the signals really do fire;
        * jpg and zip sit at high entropy too - so entropy ALONE would flag innocent
          files, which is why the real detector combines several signals.

Run:  python demo_entropy.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ransomguard import config, entropy
from tools.make_test_files import build_corpus

TEXT_FILE = config.PROTECTED_DIR / "documents" / "essay.txt"
JPG_FILE = config.PROTECTED_DIR / "media" / "photo.jpg"
ZIP_FILE = config.PROTECTED_DIR / "archives" / "project.zip"


def ensure_corpus() -> None:
    """Build the test corpus if the demo files are not there yet."""
    if TEXT_FILE.exists() and JPG_FILE.exists() and ZIP_FILE.exists():
        return
    print("test corpus missing - generating it first ...")
    config.PROTECTED_DIR.mkdir(parents=True, exist_ok=True)
    build_corpus(config.PROTECTED_DIR, scale=1, seed=1234)


def encrypt_copy(source: Path, target: Path) -> Path:
    """
    AES-256-GCM encrypt `source` into `target`, exactly the way the simulator will.

    Layout on disk: [12-byte nonce][ciphertext + 16-byte GCM tag]. GCM is an AEAD mode,
    so the tag also lets us detect tampering - and it means the ciphertext is
    indistinguishable from random bytes, which is the whole point of the demo.
    """
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, source.read_bytes(), None)
    config.ensure_inside(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(nonce + ciphertext)
    return target


def row(label: str, path: Path) -> str:
    signals = entropy.analyse_file(path)
    magic = {True: "ok", False: "BROKEN", None: "n/a"}[signals.magic_ok]
    verdict = "looks random" if signals.looks_random else "structured"
    return (
        f"{label:<26} {signals.size / 1024:>8.1f} KB "
        f"{signals.entropy:>8.3f} {signals.chi_square:>14,.0f} "
        f"{magic:>8} {verdict:>14}"
    )


def main() -> int:
    ensure_corpus()
    encrypted = encrypt_copy(TEXT_FILE, config.DEMO_DIR / "essay.txt.locked")

    header = (
        f"{'file':<26} {'size':>11} {'entropy':>8} {'chi-square':>14} "
        f"{'magic':>8} {'verdict':>14}"
    )
    print()
    print(header)
    print("-" * len(header))
    print(row("essay.txt (plain text)", TEXT_FILE))
    print(row("photo.jpg (compressed)", JPG_FILE))
    print(row("project.zip (compressed)", ZIP_FILE))
    print(row("essay.txt.locked (AES)", encrypted))
    print("-" * len(header))
    print(
        f"\nmax entropy = {entropy.MAX_ENTROPY} bits/byte; "
        f"uniform-random chi-square ~ 255 (255 degrees of freedom)."
        f"\nflag-as-random rule: entropy >= {config.HIGH_ENTROPY} "
        f"AND chi-square <= {config.CHI_SQUARE_RANDOM_MAX}"
    )
    print(
        "note: jpg/zip are also high entropy, so entropy alone is not enough - "
        "the detector also uses magic bytes, canary files and process behaviour.\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
