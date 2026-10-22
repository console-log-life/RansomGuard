"""
test_crypto_protection.py

WHAT: tests the cryptographic hardening of the backup, manifest and event log:
      AES-256-GCM encrypted backups, the HMAC-signed manifest, and the hash-chained log.

WHY : these defences only count if tampering is actually DETECTED. Each test therefore
      makes the damage and proves the system catches it: a flipped manifest byte is
      rejected, a forged backup blob fails its GCM tag, and an edited log line breaks the
      chain. A defence that silently accepts tampered data would be worse than none.
"""

from __future__ import annotations

import hashlib
import os

import pytest

from ransomguard import backup as backup_mod
from ransomguard import config, recovery
from ransomguard.logger import EventLogger, GENESIS_HASH, verify_log


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    sb = tmp_path / "sandbox"
    protected = sb / "protected"
    protected.mkdir(parents=True)
    monkeypatch.setattr(config, "SANDBOX", sb)
    monkeypatch.setattr(config, "PROTECTED_DIR", protected)
    monkeypatch.setattr(config, "BACKUP_DIR", sb / ".backup")
    monkeypatch.setattr(config, "MANIFEST_FILE", sb / ".backup" / "manifest.json")
    monkeypatch.setattr(config, "BACKUP_KEY_FILE", sb / "backup_key.bin")
    (protected / "report.pdf").write_bytes(b"%PDF-1.4\n" + b"body " * 300)
    (protected / "notes.txt").write_text("secret notes " * 80, encoding="utf-8")
    return sb, protected


# ---------------------------------------------------- A1: encrypted backups
def test_backup_files_are_encrypted_not_plaintext(sandbox):
    _, protected = sandbox
    backup_mod.build_backup(protected)
    blob = (config.BACKUP_DIR / "notes.txt").read_bytes()
    original = (protected / "notes.txt").read_bytes()
    assert blob != original                 # stored as ciphertext
    assert b"secret notes" not in blob      # plaintext is not recoverable by eye
    # It decrypts back to exactly the original, with the path bound in.
    aes_key, _ = backup_mod._subkeys(backup_mod.load_or_create_key())
    assert backup_mod.decrypt_blob(blob, "notes.txt", aes_key) == original


def test_backup_blob_bound_to_its_path(sandbox):
    _, protected = sandbox
    backup_mod.build_backup(protected)
    aes_key, _ = backup_mod._subkeys(backup_mod.load_or_create_key())
    blob = (config.BACKUP_DIR / "notes.txt").read_bytes()
    # Decrypting a blob under the WRONG path must fail the GCM check (no blob-swapping).
    with pytest.raises(Exception):
        backup_mod.decrypt_blob(blob, "report.pdf", aes_key)


def test_recovery_rejects_forged_backup_blob(sandbox):
    _, protected = sandbox
    backup_mod.build_backup(protected)
    # Corrupt a backup blob (as if an attacker rewrote it) and damage the live file.
    victim = config.BACKUP_DIR / "notes.txt"
    data = bytearray(victim.read_bytes())
    data[-1] ^= 0x01
    victim.write_bytes(bytes(data))
    (protected / "notes.txt").write_bytes(os.urandom(2048))

    result = recovery.recover(protected)
    assert result.failed >= 1              # GCM verify failed, refused to restore garbage
    assert result.restored == 0
    assert any("GCM" in d for d in result.details)


# ---------------------------------------------------- A2: signed manifest
def test_manifest_is_signed_and_verifies(sandbox):
    _, protected = sandbox
    backup_mod.build_backup(protected)
    manifest = backup_mod.load_manifest()   # verify=True by default, must not raise
    assert "report.pdf" in manifest


def test_flipped_manifest_byte_is_detected(sandbox):
    _, protected = sandbox
    backup_mod.build_backup(protected)
    path = config.MANIFEST_FILE
    text = path.read_text(encoding="utf-8")
    # Flip one hex digit of a stored hash - the smallest possible tamper.
    idx = text.index('"sha256": "') + len('"sha256": "')
    flipped = "0" if text[idx] != "0" else "1"
    path.write_text(text[:idx] + flipped + text[idx + 1:], encoding="utf-8")

    with pytest.raises(backup_mod.ManifestTampered):
        backup_mod.load_manifest()


def test_recovery_refuses_tampered_manifest(sandbox):
    _, protected = sandbox
    backup_mod.build_backup(protected)
    path = config.MANIFEST_FILE
    text = path.read_text(encoding="utf-8")
    # Change a real value (a stored hash digit): the HMAC signs the DATA, so this is caught.
    idx = text.index('"sha256": "') + len('"sha256": "')
    flipped = "0" if text[idx] != "0" else "1"
    path.write_text(text[:idx] + flipped + text[idx + 1:], encoding="utf-8")
    (protected / "notes.txt").write_bytes(os.urandom(1024))

    result = recovery.recover(protected)
    assert result.manifest_ok is False
    assert result.restored == 0            # refused to restore against an unsigned manifest


# ---------------------------------------------------- A3: hash-chained log
def test_log_is_hash_chained(tmp_path):
    log = EventLogger(path=tmp_path / "events.jsonl", echo=False)
    first = log.log("startup", a=1)
    second = log.log("fs_event", b=2)
    assert first["prev"] == GENESIS_HASH
    assert second["prev"] != GENESIS_HASH   # points at the first line's hash
    ok, bad = verify_log(tmp_path / "events.jsonl")
    assert ok and bad == -1


def test_edited_log_line_breaks_the_chain(tmp_path):
    path = tmp_path / "events.jsonl"
    log = EventLogger(path=path, echo=False)
    for i in range(5):
        log.log("fs_event", i=i, score=i * 10)
    assert verify_log(path) == (True, -1)

    # Tamper with the 3rd line (index 2) - e.g. hide a malicious event by editing it.
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[2] = lines[2].replace('"score": 20', '"score": 0')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, bad = verify_log(path)
    assert ok is False
    # The break surfaces at line 3: its stored `prev` no longer matches the (now edited)
    # line 2's hash. That is exactly how a hash chain pinpoints tampering - at the first
    # line whose back-pointer is inconsistent with the line before it.
    assert bad == 3


def test_deleted_log_line_breaks_the_chain(tmp_path):
    path = tmp_path / "events.jsonl"
    log = EventLogger(path=path, echo=False)
    for i in range(4):
        log.log("fs_event", i=i)
    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[1]                            # remove a line to hide activity
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, bad = verify_log(path)
    assert ok is False
