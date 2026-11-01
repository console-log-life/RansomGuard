"""
test_header_kept.py

WHAT: tests the header-kept attack variant and the structural-validity check that catches it.

WHY : header-kept encryption keeps a file's real magic bytes and encrypts only the body, to
      slip past a naive "magic intact -> trust it" gate. These tests prove (1) it is still
      fully reversible from the saved key, (2) it really does keep the magic yet fail the
      structural check, and (3) the scorer therefore still flags it - while a genuinely valid
      archive/image is NOT flagged.
"""

from __future__ import annotations

import gzip
import io
import os
import zipfile

from ransomguard import config, entropy
from ransomguard.baseline import BaselineEntry
from ransomguard.scorer import evaluate_signals
from simulator import container


def _key():
    return os.urandom(32)


# ------------------------------------------------- reversibility
def test_header_kept_round_trips(tmp_path):
    key = _key()
    original = b"%PDF-1.7\n" + os.urandom(40000) + b"\n%%EOF\n"
    blob = container.make_header_kept(original, key, "doc.pdf", keep=4096)
    assert container.is_header_kept(blob)
    assert blob[:9] == b"%PDF-1.7\n"                 # original header preserved
    name, restored = container.rebuild_header_kept(blob, key)
    assert name == "doc.pdf" and restored == original


def test_header_kept_wrong_key_fails(tmp_path):
    blob = container.make_header_kept(b"PK\x03\x04" + os.urandom(20000), _key(), "a.zip")
    import pytest
    with pytest.raises(Exception):
        container.rebuild_header_kept(blob, _key())   # different key -> GCM tag fails


# ------------------------------------------------- structural checks
def test_structural_ok_true_for_valid_zip_and_png(tmp_path):
    z = tmp_path / "a.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("x.txt", "hello " * 1000)
    assert entropy.analyse_file(z).structural_ok is True

    # a real 1x1 PNG with correct CRCs
    png = tmp_path / "b.png"
    sig = b"\x89PNG\r\n\x1a\n"
    def chunk(t, d):
        import struct, zlib
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    ihdr = chunk(b"IHDR", (1).to_bytes(4, "big") + (1).to_bytes(4, "big") + b"\x08\x02\x00\x00\x00")
    import zlib as _z
    idat = chunk(b"IDAT", _z.compress(b"\x00\xff\x00\x00"))
    png.write_bytes(sig + ihdr + idat + chunk(b"IEND", b""))
    assert entropy.analyse_file(png).structural_ok is True


def test_structural_ok_false_for_header_kept_zip_and_png(tmp_path):
    key = _key()
    # valid zip, then header-kept encrypted: keeps PK magic, body corrupt -> testzip fails
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("x.txt", "data " * 5000)
    z = tmp_path / "a.zip"
    z.write_bytes(container.make_header_kept(buf.getvalue(), key, "a.zip", keep=64))
    sig = entropy.analyse_file(z)
    assert sig.magic_ok is True            # PK header still there
    assert sig.structural_ok is False      # but the archive no longer opens

    # same for a gzip
    raw = io.BytesIO()
    with gzip.GzipFile(fileobj=raw, mode="wb") as gzf:
        gzf.write(b"hello " * 5000)
    g = tmp_path / "c.gz"
    g.write_bytes(container.make_header_kept(raw.getvalue(), key, "c.gz", keep=4))
    assert entropy.analyse_file(g).structural_ok is False


def test_scorer_flags_header_kept_but_not_valid_archive(tmp_path):
    key = _key()
    # baseline: the file used to be a valid, low-entropy-ish document
    base = BaselineEntry(entropy=3.0, sha256="x", size=40000, ext=".zip")

    # Incompressible content so the zip (and its header-kept encrypted body) is high entropy.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("x.bin", os.urandom(40000))
    valid = tmp_path / "ok.zip"
    valid.write_bytes(buf.getvalue())
    hk = tmp_path / "hk.zip"
    hk.write_bytes(container.make_header_kept(buf.getvalue(), key, "hk.zip", keep=64))

    valid_codes = {r.code for r in evaluate_signals(entropy.analyse_file(valid), base, canary_touched=False)}
    hk_codes = {r.code for r in evaluate_signals(entropy.analyse_file(hk), base, canary_touched=False)}
    assert "entropy_jump" not in valid_codes          # valid archive: not flagged on entropy
    assert "entropy_jump" in hk_codes or "low_chi_square" in hk_codes  # header-kept: flagged
