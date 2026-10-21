"""
test_entropy.py

WHAT: unit tests for the measurement layer (entropy, chi-square, magic bytes) and for the
      sandbox safety guard.

WHY : every later decision (score, kill, restore) is built on these numbers. If entropy
      of random data were not ~8.0, or the magic-byte check returned False for a healthy
      pdf, the whole detector would be wrong in a way that is very hard to see in a live
      demo. These tests pin the maths down with cases we can reason about by hand.
"""

from __future__ import annotations

import os
import zipfile

import pytest

from ransomguard import config, entropy


# --------------------------------------------------------------------------- entropy
def test_entropy_of_empty_data_is_zero():
    assert entropy.shannon_entropy(b"") == 0.0


def test_entropy_of_single_repeated_byte_is_zero():
    # p(x) = 1 for one value -> H = -1 * log2(1) = 0: no information at all.
    assert entropy.shannon_entropy(b"A" * 5000) == 0.0


def test_entropy_of_two_equally_likely_bytes_is_one_bit():
    assert entropy.shannon_entropy(b"AB" * 500) == pytest.approx(1.0)


def test_entropy_of_all_256_values_is_maximum():
    # Every byte value exactly once -> perfectly uniform -> H = log2(256) = 8.
    assert entropy.shannon_entropy(bytes(range(256))) == pytest.approx(8.0)


def test_entropy_of_random_data_is_near_maximum():
    assert entropy.shannon_entropy(os.urandom(65536)) > 7.95


def test_entropy_of_english_text_is_low():
    text = ("the quick brown fox jumps over the lazy dog. " * 400).encode()
    assert entropy.shannon_entropy(text) < 5.0


# ------------------------------------------------------------------------ chi-square
def test_chi_square_of_empty_data_is_zero():
    assert entropy.chi_square(b"") == 0.0


def test_chi_square_of_random_data_is_small():
    # 255 degrees of freedom -> uniform data lands near 255, well under the threshold.
    assert entropy.chi_square(os.urandom(65536)) < config.CHI_SQUARE_RANDOM_MAX


def test_chi_square_of_text_is_huge():
    text = ("attack at dawn " * 2000).encode()
    assert entropy.chi_square(text) > 10_000


# ----------------------------------------------------------------------- looks_random
def test_looks_random_true_for_ciphertext_like_data():
    assert entropy.looks_random(os.urandom(65536)) is True


def test_looks_random_false_for_text_and_empty():
    assert entropy.looks_random(b"hello world " * 500) is False
    assert entropy.looks_random(b"") is False


# ------------------------------------------------------------------------ file access
def test_file_entropy_only_reads_the_sample_window(tmp_path):
    # First 1 KB is a constant byte (H = 0), the rest is random. With max_bytes=1024 we
    # must see 0.0 - proof that we really do sample only the head of the file.
    path = tmp_path / "mixed.bin"
    path.write_bytes(b"\x00" * 1024 + os.urandom(20000))
    assert entropy.file_entropy(path, max_bytes=1024) == 0.0
    assert entropy.file_entropy(path) > 7.0


# ----------------------------------------------------------------------- magic bytes
def test_magic_ok_for_healthy_pdf(tmp_path):
    path = tmp_path / "report.pdf"
    path.write_bytes(b"%PDF-1.7\n% body\n%%EOF\n")
    assert entropy.magic_bytes_ok(path) is True


def test_magic_broken_when_pdf_is_encrypted_in_place(tmp_path):
    # This is literally what ransomware does: same name, random content.
    path = tmp_path / "report.pdf"
    path.write_bytes(os.urandom(4096))
    assert entropy.magic_bytes_ok(path) is False


def test_magic_ok_for_real_zip_and_docx(tmp_path):
    for name in ("project.zip", "thesis.docx"):
        path = tmp_path / name
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("a.txt", "hello")
        assert entropy.magic_bytes_ok(path) is True


def test_magic_ok_for_jpeg_and_mp4(tmp_path):
    jpg = tmp_path / "photo.jpg"
    jpg.write_bytes(b"\xff\xd8\xff\xe0" + os.urandom(100))
    assert entropy.magic_bytes_ok(jpg) is True

    mp4 = tmp_path / "clip.mp4"
    mp4.write_bytes(b"\x00\x00\x00\x18ftypisom" + os.urandom(100))
    assert entropy.magic_bytes_ok(mp4) is True


def test_magic_unknown_for_text_and_locked_extensions(tmp_path):
    # None means "no signature defined", which must never be treated as evidence.
    txt = tmp_path / "notes.txt"
    txt.write_text("plain")
    assert entropy.magic_bytes_ok(txt) is None

    locked = tmp_path / "notes.txt.locked"
    locked.write_bytes(os.urandom(64))
    assert entropy.magic_bytes_ok(locked) is None


def test_magic_check_on_truncated_file_does_not_crash(tmp_path):
    path = tmp_path / "tiny.png"
    path.write_bytes(b"\x89P")
    assert entropy.magic_bytes_ok(path) is False


# --------------------------------------------------------------------- analyse_file
def test_analyse_file_reports_all_signals_for_encrypted_pdf(tmp_path):
    path = tmp_path / "invoice.pdf"
    path.write_bytes(os.urandom(65536))
    signals = entropy.analyse_file(path)

    assert signals.ext == ".pdf"
    assert signals.entropy > 7.9
    assert signals.magic_ok is False
    assert signals.looks_random is True
    assert signals.as_dict()["path"] == str(path)


# ------------------------------------------------------------------- safety guard
def test_ensure_inside_accepts_sandbox_paths():
    target = config.PROTECTED_DIR / "documents" / "notes.txt"
    assert config.ensure_inside(target) == target.resolve()


def test_ensure_inside_rejects_paths_outside_sandbox(tmp_path):
    with pytest.raises(config.SandboxViolation):
        config.ensure_inside(tmp_path / "victim.txt")


def test_ensure_inside_rejects_traversal_escape():
    with pytest.raises(config.SandboxViolation):
        config.ensure_inside(config.PROTECTED_DIR / ".." / ".." / "escaped.txt")
