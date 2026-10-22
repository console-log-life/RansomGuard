"""
test_recovery.py

WHAT: tests the backup snapshot/refresh and the hash-verified recovery.

WHY : recovery is the payoff of the whole project, and it must be provably correct: a file
      it claims to have "restored" has to be byte-identical to the original, and the
      ransomware artifacts have to be gone. These tests simulate the exact damage patterns
      ransomware produces - encrypt-in-place, rename-to-.locked, delete - and assert the
      folder comes back to its clean state, verified by hash.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ransomguard import backup as backup_mod
from ransomguard import config, recovery
from ransomguard.baseline import sha256_file


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    sb = tmp_path / "sandbox"
    protected = sb / "protected"
    (protected / "documents").mkdir(parents=True)
    monkeypatch.setattr(config, "SANDBOX", sb)
    monkeypatch.setattr(config, "PROTECTED_DIR", protected)
    monkeypatch.setattr(config, "BACKUP_DIR", sb / ".backup")
    monkeypatch.setattr(config, "MANIFEST_FILE", sb / ".backup" / "manifest.json")
    monkeypatch.setattr(config, "BACKUP_KEY_FILE", sb / "backup_key.bin")

    (protected / "notes.txt").write_text("hello world " * 100, encoding="utf-8")
    (protected / "documents" / "report.pdf").write_bytes(b"%PDF-1.4\n" + b"body " * 300)
    (protected / "documents" / "data.csv").write_text("a,b,c\n1,2,3\n" * 50, encoding="utf-8")
    return sb, protected


def _snapshot(folder: Path) -> dict[str, str]:
    return {
        str(p.relative_to(folder)): sha256_file(p)
        for p in folder.rglob("*")
        if p.is_file()
    }


# ------------------------------------------------------------------ backup
def test_build_backup_copies_every_file_and_manifest(sandbox):
    _, protected = sandbox
    manifest = backup_mod.build_backup(protected)
    assert len(manifest) == 3
    assert (config.BACKUP_DIR / "notes.txt").exists()
    assert (config.BACKUP_DIR / "documents" / "report.pdf").exists()

    loaded = backup_mod.load_manifest()
    assert {k: v.sha256 for k, v in loaded.items()} == {k: v.sha256 for k, v in manifest.items()}


def test_refresh_folds_in_a_benign_edit(sandbox):
    _, protected = sandbox
    backup_mod.build_backup(protected)
    # A legitimate edit: still text, low entropy, magic fine.
    (protected / "notes.txt").write_text("edited text " * 120, encoding="utf-8")
    n = backup_mod.refresh_clean(protected)
    assert n == 1
    # The backup is now ciphertext, so compare via the manifest hash and a decrypt.
    manifest = backup_mod.load_manifest()
    assert manifest["notes.txt"].sha256 == sha256_file(protected / "notes.txt")
    aes_key, _ = backup_mod._subkeys(backup_mod.load_or_create_key())
    blob = (config.BACKUP_DIR / "notes.txt").read_bytes()
    assert backup_mod.decrypt_blob(blob, "notes.txt", aes_key) == (protected / "notes.txt").read_bytes()


def test_refresh_skips_encrypted_file_and_during_alert(sandbox):
    _, protected = sandbox
    backup_mod.build_backup(protected)
    good_hash = sha256_file(config.BACKUP_DIR / "documents" / "report.pdf")

    # Encrypt the pdf in place: magic bytes gone, high entropy -> must NOT enter the backup.
    (protected / "documents" / "report.pdf").write_bytes(os.urandom(4096))
    assert backup_mod.refresh_clean(protected) == 0
    assert sha256_file(config.BACKUP_DIR / "documents" / "report.pdf") == good_hash

    # And even a benign change is ignored while an alert is active.
    (protected / "notes.txt").write_text("benign but during attack", encoding="utf-8")
    assert backup_mod.refresh_clean(protected, active_alert=True) == 0


# ---------------------------------------------------------------- recovery
def test_recover_restores_encrypted_in_place_file(sandbox):
    _, protected = sandbox
    backup_mod.build_backup(protected)
    clean = _snapshot(protected)

    pdf = protected / "documents" / "report.pdf"
    pdf.write_bytes(os.urandom(8192))  # encrypted in place, same name

    result = recovery.recover(protected)
    assert result.restored == 1
    assert result.failed == 0
    assert _snapshot(protected) == clean  # byte-for-byte back to clean


def test_recover_handles_locked_rename_and_delete(sandbox):
    _, protected = sandbox
    backup_mod.build_backup(protected)
    clean = _snapshot(protected)

    # Pattern 1: rename-to-.locked (original deleted, encrypted copy added).
    notes = protected / "notes.txt"
    (protected / "notes.txt.locked").write_bytes(os.urandom(4096))
    notes.unlink()
    # Pattern 2: outright deletion.
    (protected / "documents" / "data.csv").unlink()

    result = recovery.recover(protected)
    assert result.restored == 2          # notes.txt and data.csv both restored
    assert result.removed == 1           # the .locked artifact removed
    assert not (protected / "notes.txt.locked").exists()
    assert _snapshot(protected) == clean


def test_recover_reports_failure_when_backup_missing(sandbox):
    _, protected = sandbox
    backup_mod.build_backup(protected)
    # Delete the backup copy, then damage the live file: recovery cannot succeed and must
    # say so rather than silently claim success.
    (config.BACKUP_DIR / "notes.txt").unlink()
    (protected / "notes.txt").write_bytes(os.urandom(2048))

    result = recovery.recover(protected)
    assert result.affected >= 1
    assert result.failed >= 1
    assert result.restored == 0


def test_recover_is_noop_on_clean_folder(sandbox):
    _, protected = sandbox
    backup_mod.build_backup(protected)
    result = recovery.recover(protected)
    assert result.affected == 0 and result.restored == 0 and result.removed == 0
