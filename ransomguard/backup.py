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

CRYPTOGRAPHIC PROTECTION (so the backup itself resists tampering):
  * Every backup file is stored as AES-256-GCM ciphertext, not a plain copy. The relative
    path is bound in as GCM associated data, so a blob cannot be swapped between paths, and
    the GCM tag detects any bit-flip. Recovery decrypts and verifies the tag before it will
    restore anything.
  * The manifest is signed with HMAC-SHA256. Recovery verifies the signature FIRST and
    refuses to use a manifest that has been altered - otherwise an attacker could rewrite
    the "known-good" hashes and defeat verification.
  * The AES key and the HMAC key are two independent subkeys derived from one master key in
    config.BACKUP_KEY_FILE. For this student project the master key is a file in the
    sandbox; a real deployment would keep it in an OS keystore / TPM / HSM off the protected
    disk. This is documented, not hidden.

The backup lives inside the sandbox and is excluded from the watcher, the simulator and the
baseline scan, so it is never itself treated as user data or attacked.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config, entropy
from .baseline import sha256_file

NONCE_SIZE = 12  # 96-bit nonce, the standard size for AES-GCM


class ManifestTampered(Exception):
    """Raised when the manifest's HMAC signature does not verify."""


def load_or_create_key() -> bytes:
    """Return the 32-byte master key, creating it on first use.

    In production this comes from an OS keystore / TPM; here it is a sandbox file.
    """
    path = config.ensure_inside(config.BACKUP_KEY_FILE, config.SANDBOX)
    if path.exists():
        return path.read_bytes()
    key = os.urandom(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key)
    return key


def _subkeys(master: bytes) -> tuple[bytes, bytes]:
    """Derive independent AES and HMAC keys from the master (domain-separated SHA-256)."""
    aes_key = hashlib.sha256(master + b"ransomguard-backup-aes").digest()
    hmac_key = hashlib.sha256(master + b"ransomguard-manifest-hmac").digest()
    return aes_key, hmac_key


def encrypt_blob(data: bytes, relpath: str, aes_key: bytes) -> bytes:
    """AES-256-GCM encrypt `data`, binding `relpath` as associated data."""
    nonce = os.urandom(NONCE_SIZE)
    ct = AESGCM(aes_key).encrypt(nonce, data, relpath.encode("utf-8"))
    return nonce + ct


def decrypt_blob(blob: bytes, relpath: str, aes_key: bytes) -> bytes:
    """Decrypt a backup blob, verifying the GCM tag and the bound path. Raises InvalidTag."""
    nonce, ct = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    return AESGCM(aes_key).decrypt(nonce, ct, relpath.encode("utf-8"))


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
    import shutil

    root = config.ensure_inside(root or config.PROTECTED_DIR)
    backup_dir = config.ensure_inside(backup_dir or config.BACKUP_DIR, config.SANDBOX)
    aes_key, _ = _subkeys(load_or_create_key())
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
        # Store the backup as AES-GCM ciphertext (manifest records the PLAINTEXT hash).
        dest.write_bytes(encrypt_blob(path.read_bytes(), relpath, aes_key))
        manifest[relpath] = _scan(path)

    save_manifest(manifest, backup_dir)
    return manifest


def _manifest_signing_bytes(payload: dict) -> bytes:
    """Canonical bytes signed by the HMAC: the created-time + the files map, stable order."""
    return json.dumps(
        {"created": payload["created"], "files": payload["files"]},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def save_manifest(manifest: dict[str, ManifestEntry], backup_dir: Path | None = None) -> Path:
    backup_dir = backup_dir or config.BACKUP_DIR
    path = config.ensure_inside(backup_dir / config.MANIFEST_FILE.name, config.SANDBOX)
    path.parent.mkdir(parents=True, exist_ok=True)
    _, hmac_key = _subkeys(load_or_create_key())
    payload = {"created": time.time(), "files": {k: v.as_dict() for k, v in manifest.items()}}
    payload["hmac"] = hmac.new(hmac_key, _manifest_signing_bytes(payload), hashlib.sha256).hexdigest()
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def load_manifest(backup_dir: Path | None = None, verify: bool = True) -> dict[str, ManifestEntry]:
    """
    Load the manifest, verifying its HMAC signature first.

    If `verify` is True (the default, always used by recovery) a missing or wrong signature
    raises ManifestTampered - we refuse to trust hashes an attacker might have rewritten.
    """
    backup_dir = backup_dir or config.BACKUP_DIR
    path = backup_dir / config.MANIFEST_FILE.name
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if verify:
        _, hmac_key = _subkeys(load_or_create_key())
        expected = hmac.new(hmac_key, _manifest_signing_bytes(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, payload.get("hmac", "")):
            raise ManifestTampered(f"manifest HMAC mismatch at {path}")
    raw = payload.get("files", {})
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
    aes_key, _ = _subkeys(load_or_create_key())

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
        dest.write_bytes(encrypt_blob(path.read_bytes(), relpath, aes_key))
        manifest[relpath] = _scan(path)
        refreshed += 1

    if refreshed:
        save_manifest(manifest, backup_dir)
    return refreshed
