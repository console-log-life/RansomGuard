"""
recovery.py

WHAT: after the attacker has been stopped, this puts the folder back the way it was. It
      compares every file against the SHA-256 manifest, restores anything that was encrypted
      in place or deleted from the clean backup, removes the ransomware artifacts (the
      .locked / .enc / ... copies), and verifies each restored file by hash.

WHY : this is the "recovery" half of the project's title and the reason the whole thing is
      worth doing - a detector that only kills the process still leaves you with encrypted
      files. Because recovery restores from our own hash-verified backup (not from the
      attacker's key), it works against REAL ransomware too, where no key is available.
      Every restored file is re-hashed and checked against the manifest, so we can report
      with certainty how many files were truly recovered.

Unlike simulator/undo.py (which trusts the saved AES key and is only for our simulator),
recovery makes no assumption about how the files were damaged.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidTag

from . import backup as backup_mod
from . import config
from .baseline import sha256_file


@dataclass
class RecoveryResult:
    affected: int = 0          # files that were missing, modified, or ransomware copies
    restored: int = 0          # files put back and hash-verified against the manifest
    failed: int = 0            # files we could not restore or that failed verification
    removed: int = 0           # ransomware artifacts (.locked etc.) deleted
    manifest_ok: bool = True   # False if the manifest HMAC failed (we refuse to restore)
    details: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"affected={self.affected} restored={self.restored} "
            f"failed={self.failed} removed_artifacts={self.removed} manifest_ok={self.manifest_ok}"
        )


def _is_ransomware_artifact(path: Path) -> bool:
    """A leftover encrypted copy: a suspicious extension not part of the clean baseline."""
    return path.suffix.lower() in config.SUSPICIOUS_EXTS


def recover(
    root: Path | None = None,
    backup_dir: Path | None = None,
) -> RecoveryResult:
    """
    Restore the protected folder from the backup + manifest, and clean up artifacts.

    Steps:
      1. For every file in the manifest, if the live file is missing or its hash differs,
         copy the clean version back and verify the restored hash matches the manifest.
      2. Delete ransomware artifacts (*.locked and other suspicious extensions) that are
         not themselves part of the manifest.
    """
    root = config.ensure_inside(root or config.PROTECTED_DIR)
    backup_dir = config.ensure_inside(backup_dir or config.BACKUP_DIR, config.SANDBOX)
    result = RecoveryResult()

    # Verify the manifest signature BEFORE trusting a single hash in it. A tampered
    # manifest is refused outright - we will not restore against attacker-chosen hashes.
    try:
        manifest = backup_mod.load_manifest(backup_dir)
    except backup_mod.ManifestTampered as exc:
        result.manifest_ok = False
        result.details.append(f"refusing tampered manifest: {exc}")
        return result

    aes_key, _ = backup_mod._subkeys(backup_mod.load_or_create_key())

    # ---- 1. restore originals that were encrypted-in-place or deleted ----------------
    for relpath, entry in manifest.items():
        live = config.ensure_inside(root / relpath)
        source = backup_mod.backup_copy_of(relpath, backup_dir)

        try:
            current_hash = sha256_file(live) if live.exists() else None
        except OSError:
            current_hash = None

        if current_hash == entry.sha256:
            continue  # this file is fine, leave it alone

        result.affected += 1
        if not source.exists():
            result.failed += 1
            result.details.append(f"no backup for {relpath}")
            continue
        try:
            # Decrypt the backup blob and verify the GCM tag (and the path binding) BEFORE
            # writing anything. A corrupted/forged blob raises InvalidTag and is not restored.
            plaintext = backup_mod.decrypt_blob(source.read_bytes(), relpath, aes_key)
        except (InvalidTag, ValueError) as exc:
            result.failed += 1
            result.details.append(f"backup blob failed GCM verify: {relpath} ({exc})")
            continue
        # Second check: the decrypted bytes must hash to exactly the manifest value.
        if hashlib.sha256(plaintext).hexdigest() != entry.sha256:
            result.failed += 1
            result.details.append(f"decrypted hash mismatch: {relpath}")
            continue
        try:
            live.parent.mkdir(parents=True, exist_ok=True)
            live.write_bytes(plaintext)
            result.restored += 1
        except OSError as exc:
            result.failed += 1
            result.details.append(f"restore failed {relpath}: {exc}")

    # ---- 2. remove ransomware artifacts (the .locked copies) -------------------------
    manifest_abs = {str((root / rel).resolve()) for rel in manifest}
    backup_root = backup_dir.resolve()
    for path in root.rglob("*"):
        if path.is_dir() or backup_root in path.resolve().parents:
            continue
        if _is_ransomware_artifact(path) and str(path.resolve()) not in manifest_abs:
            try:
                config.ensure_inside(path).unlink()
                result.removed += 1
            except OSError as exc:
                result.details.append(f"could not remove {path.name}: {exc}")

    return result
