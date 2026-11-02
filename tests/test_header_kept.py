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


# ------------------------------------------------- media structural checks (item 1)
def _mp4_bytes(payload: bytes = b"\x00" * 2000) -> bytes:
    """Minimal ISO-BMFF: ftyp + moov + mdat, sizes chaining exactly to EOF."""
    def box(t, body):
        return (len(body) + 8).to_bytes(4, "big") + t + body
    return box(b"ftyp", b"isom\x00\x00\x02\x00isomiso2") + box(b"moov", b"\x00" * 64) + box(b"mdat", payload)


def _mkv_bytes(payload_len: int = 2000) -> bytes:
    """Minimal EBML: header + Segment whose children chain to the declared segment size."""
    hdr_body = b"\x42\x86\x81\x01\x42\xf7\x81\x01"           # EBMLVersion, EBMLReadVersion
    ebml = b"\x1a\x45\xdf\xa3" + bytes([0x80 | len(hdr_body)]) + hdr_body

    info = b"\x15\x49\xa9\x66" + bytes([0x80 | 4]) + b"\x00" * 4          # Info
    void = b"\xec" + bytes([0x80 | 0])                                    # empty Void
    cluster = b"\x1f\x43\xb6\x75" + bytes([0x80 | 0])                     # empty Cluster
    big = b"\xec" + bytes([0x40 | ((payload_len >> 8) & 0x3F), payload_len & 0xFF])
    seg_body = info + void + cluster + big + b"\x00" * payload_len         # Void w/ 2-byte size

    # Segment ID + an 8-byte size vint (0x01 marker + 7 size bytes)
    seg_header = b"\x18\x53\x80\x67" + bytes([0x01]) + len(seg_body).to_bytes(7, "big")
    return ebml + seg_header + seg_body


def _mp3_bytes(frames: int = 20) -> bytes:
    """Minimal MPEG1 Layer III stream: 128 kbps / 44.1 kHz -> 417-byte frames."""
    header = b"\xff\xfb\x90\x00"
    return (header + b"\x00" * (417 - 4)) * frames


def test_mp4_structural_valid_and_header_kept_detected(tmp_path):
    good = tmp_path / "a.mp4"
    good.write_bytes(_mp4_bytes())
    assert entropy.analyse_file(good).structural_ok is True

    bad = tmp_path / "b.mp4"
    bad.write_bytes(container.make_header_kept(_mp4_bytes(), _key(), "b.mp4", keep=64))
    s = entropy.analyse_file(bad)
    assert s.magic_ok is True and s.structural_ok is False   # ftyp kept, box chain broken


def test_mkv_structural_valid_and_header_kept_detected(tmp_path):
    good = tmp_path / "a.mkv"
    good.write_bytes(_mkv_bytes())
    assert entropy.analyse_file(good).structural_ok is True

    bad = tmp_path / "b.mkv"
    bad.write_bytes(container.make_header_kept(_mkv_bytes(), _key(), "b.mkv", keep=16))
    s = entropy.analyse_file(bad)
    assert s.magic_ok is True and s.structural_ok is False   # EBML sig kept, children broken


def test_mp3_structural_valid_and_header_kept_detected(tmp_path):
    good = tmp_path / "a.mp3"
    good.write_bytes(_mp3_bytes())
    assert entropy.analyse_file(good).structural_ok is True

    bad = tmp_path / "b.mp3"
    bad.write_bytes(container.make_header_kept(_mp3_bytes(), _key(), "b.mp3", keep=8))
    s = entropy.analyse_file(bad)
    assert s.structural_ok is False                          # frame-sync chain broken
