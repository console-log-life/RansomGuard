"""
entropy.py

WHAT: measures how "random" the bytes of a file look, and whether the file still has the
      header (magic bytes) that its extension promises.

WHY : ransomware encrypts files. Good ciphertext is indistinguishable from random noise,
      so after encryption three things change at once:
        1. Shannon entropy jumps towards its maximum of 8.0 bits per byte.
           (English text ~4.2, CSV/JSON ~4-5, already-compressed jpg/zip ~7.9.)
        2. The byte distribution becomes uniform, which a chi-square test detects.
        3. The file header is destroyed: a .pdf no longer starts with "%PDF".
      Each signal alone gives false positives (a .zip is also high entropy), which is
      exactly why scorer.py combines them instead of trusting any single one.

This module is pure measurement: it never writes or deletes anything.
"""

from __future__ import annotations

import gzip
import math
import zipfile
import zlib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from . import config

MAX_ENTROPY: float = 8.0  # one byte carries at most 8 bits of information

# ---------------------------------------------------------------------------
# File-type signatures: extension -> list of accepted (offset, magic bytes).
# A file is "ok" if ANY alternative matches, because e.g. a zip may be empty.
# ---------------------------------------------------------------------------
MAGIC_SIGNATURES: dict[str, tuple[tuple[int, bytes], ...]] = {
    ".pdf": ((0, b"%PDF"),),
    # DOCX/XLSX/PPTX/ODT are really zip containers, so they share the zip signature.
    ".zip": ((0, b"PK\x03\x04"), (0, b"PK\x05\x06"), (0, b"PK\x07\x08")),
    ".docx": ((0, b"PK\x03\x04"),),
    ".xlsx": ((0, b"PK\x03\x04"),),
    ".pptx": ((0, b"PK\x03\x04"),),
    ".odt": ((0, b"PK\x03\x04"),),
    ".png": ((0, b"\x89PNG\r\n\x1a\n"),),
    ".jpg": ((0, b"\xff\xd8\xff"),),
    ".jpeg": ((0, b"\xff\xd8\xff"),),
    ".gif": ((0, b"GIF87a"), (0, b"GIF89a")),
    # ISO base media files put a 4-byte size first, then the literal box type "ftyp".
    ".mp4": ((4, b"ftyp"),),
    ".m4v": ((4, b"ftyp"),),
    ".mov": ((4, b"ftyp"),),
    ".gz": ((0, b"\x1f\x8b"),),
    ".mp3": ((0, b"ID3"), (0, b"\xff\xfb")),
    # RAR 4 and RAR 5 share the first 7 bytes; 7z has a 6-byte signature.
    ".rar": ((0, b"\x52\x61\x72\x21\x1a\x07"),),
    ".7z": ((0, b"\x37\x7a\xbc\xaf\x27\x1c"),),
    # Matroska / WebM share the EBML signature.
    ".mkv": ((0, b"\x1a\x45\xdf\xa3"),),
    ".webm": ((0, b"\x1a\x45\xdf\xa3"),),
    ".m4a": ((4, b"ftyp"),),
}

# Plain-text formats have no magic bytes at all, so there is nothing to verify.
TEXTUAL_EXTS: frozenset[str] = frozenset(
    {".txt", ".csv", ".json", ".md", ".log", ".xml", ".html", ".py", ".ini", ".cfg"}
)


# The 64 base64 symbols plus padding/newlines - used by the encoded-content heuristic.
_BASE64_BYTES = frozenset(
    (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n"
    ).encode("ascii")
)


@dataclass(frozen=True)
class FileSignals:
    """Everything entropy.py can say about one file, in one object."""

    path: Path
    size: int
    ext: str
    entropy: float          # the most suspicious window's entropy (max across offsets)
    chi_square: float
    magic_ok: bool | None   # True = header fine, False = header broken, None = unknown type
    looks_random: bool
    encoded: bool = False   # content looks base64/encoded (low-ish entropy, base64 charset)
    # Deeper than magic bytes: True = the file is STRUCTURALLY a valid instance of its type
    # (zip opens+CRCs pass, PNG chunk CRCs verify, ...), False = header may look right but the
    # structure is broken (e.g. header-kept encryption), None = no structural check for this
    # type. This is what defeats the "keep the magic bytes" evasion.
    structural_ok: bool | None = None

    def as_dict(self) -> dict[str, object]:
        """Flat dict for the JSON baseline / event log."""
        return {
            "path": str(self.path),
            "size": self.size,
            "ext": self.ext,
            "entropy": round(self.entropy, 4),
            "chi_square": round(self.chi_square, 2),
            "magic_ok": self.magic_ok,
            "looks_random": self.looks_random,
            "encoded": self.encoded,
            "structural_ok": self.structural_ok,
        }


def shannon_entropy(data: bytes) -> float:
    """
    Shannon entropy of a byte string, in bits per byte (0.0 .. 8.0).

        H = - sum over x of  p(x) * log2 p(x)

    where x runs over the 256 possible byte values and p(x) is how often that byte
    occurs in `data`. Intuition:
      * one byte repeated forever -> p = 1 for that byte  -> H = 0 (no information)
      * all 256 bytes equally likely -> p = 1/256 each    -> H = 8 (maximum)
    AES ciphertext sits at ~7.99, English text at ~4.2.
    """
    if not data:
        return 0.0

    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def chi_square(data: bytes) -> float:
    """
    Chi-square statistic of the byte distribution against a *uniform* distribution.

        X^2 = sum over x of  (observed(x) - expected)^2 / expected,
        expected = len(data) / 256   for every byte value x

    With 256 categories there are 255 degrees of freedom, so:
      * uniformly random bytes (encrypted data) -> X^2 lands near 255
      * structured data (text, CSV, headers)    -> X^2 in the thousands or more
    So a LOW chi-square means "this looks random", which is why config calls the
    threshold CHI_SQUARE_RANDOM_MAX. Returns 0.0 for empty input.
    """
    if not data:
        return 0.0

    counts = Counter(data)
    expected = len(data) / 256.0
    return sum(
        (counts.get(value, 0) - expected) ** 2 / expected for value in range(256)
    )


def read_sample(path: Path | str, max_bytes: int = config.ENTROPY_SAMPLE_BYTES) -> bytes:
    """Read at most the first `max_bytes` of a file (64 KB by default).

    Sampling the head instead of the whole file keeps the live monitor fast: a 2 GB
    video would otherwise stall every event. 64 KB is far more than enough for a
    stable entropy estimate (256 buckets, ~256 samples each).
    """
    with open(path, "rb") as handle:
        return handle.read(max_bytes)


def file_entropy(path: Path | str, max_bytes: int = config.ENTROPY_SAMPLE_BYTES) -> float:
    """Shannon entropy of the first `max_bytes` of a file. 0.0 if the file is empty."""
    return shannon_entropy(read_sample(path, max_bytes))


def magic_bytes_ok(path: Path | str, data: bytes | None = None) -> bool | None:
    """
    Does the file's header match what its extension claims?

    Returns:
        True  - the extension is known and the signature matches
        False - the extension is known and the signature does NOT match
                (this is the strong "a document got encrypted in place" signal)
        None  - we have no signature for this extension (.txt, .locked, no extension),
                so there is nothing to check. None is deliberately *not* False: an
                unknown type is not evidence of anything.
    """
    path = Path(path)
    ext = path.suffix.lower()
    signatures = MAGIC_SIGNATURES.get(ext)
    if signatures is None:
        return None  # textual or unknown extension: no header to verify

    if data is None:
        # Read just enough for the longest signature we check.
        longest = max(offset + len(magic) for offset, magic in signatures)
        with open(path, "rb") as handle:
            data = handle.read(longest)

    return any(data[offset:offset + len(magic)] == magic for offset, magic in signatures)


_ZIP_EXTS = frozenset({".zip", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".apk", ".jar"})


def _png_structurally_ok(data: bytes) -> bool:
    """Verify a PNG's chunk CRCs. A header-kept PNG keeps the signature but the IDAT CRCs
    no longer match the (now encrypted) data."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return False
    i, n = 8, len(data)
    seen_end = False
    while i + 12 <= n:
        length = int.from_bytes(data[i:i + 4], "big")
        if i + 12 + length > n:
            return False
        chunk = data[i + 4:i + 8 + length]           # type + data
        crc = int.from_bytes(data[i + 8 + length:i + 12 + length], "big")
        if (zlib.crc32(chunk) & 0xFFFFFFFF) != crc:
            return False
        if data[i + 4:i + 8] == b"IEND":
            seen_end = True
            break
        i += 12 + length
    return seen_end


def _mp4_structurally_ok(data: bytes) -> bool:
    """Walk the top-level ISO-BMFF boxes: they must chain exactly to EOF, start with 'ftyp',
    and include both 'moov' and 'mdat'. Header-kept encryption leaves 'ftyp' but destroys the
    box chain almost immediately."""
    n, pos = len(data), 0
    types: list[bytes] = []
    while pos + 8 <= n:
        size = int.from_bytes(data[pos:pos + 4], "big")
        btype = data[pos + 4:pos + 8]
        header = 8
        if size == 1:                                  # 64-bit extended size
            if pos + 16 > n:
                return False
            size = int.from_bytes(data[pos + 8:pos + 16], "big")
            header = 16
        elif size == 0:                                # box runs to EOF
            size = n - pos
        if size < header or pos + size > n:
            return False
        if not btype.isalnum() and not btype.isalpha():
            return False
        types.append(btype)
        pos += size
    return pos == n and bool(types) and types[0] == b"ftyp" \
        and b"moov" in types and b"mdat" in types


def _ebml_vint(data: bytes, pos: int, mask_id: bool) -> tuple[int, int] | None:
    """Read one EBML variable-length integer. Returns (value, bytes_consumed)."""
    if pos >= len(data):
        return None
    first = data[pos]
    if first == 0:
        return None
    length = 8 - first.bit_length() + 1
    if length < 1 or length > 8 or pos + length > len(data):
        return None
    raw = data[pos:pos + length]
    if mask_id:                                        # element IDs keep their marker bit
        return int.from_bytes(raw, "big"), length
    value = raw[0] & ((1 << (8 - length)) - 1)         # sizes strip the marker bit
    for b in raw[1:]:
        value = (value << 8) | b
    return value, length


def _mkv_structurally_ok(data: bytes) -> bool:
    """Valid EBML header followed by a Segment element whose declared size fits the file."""
    if data[:4] != b"\x1a\x45\xdf\xa3":
        return False
    hdr = _ebml_vint(data, 4, mask_id=False)           # EBML header payload size
    if hdr is None:
        return False
    size, used = hdr
    pos = 4 + used + size                              # skip the EBML header payload
    eid = _ebml_vint(data, pos, mask_id=True)
    if eid is None or eid[0] != 0x18538067:            # Segment
        return False
    pos += eid[1]
    seg = _ebml_vint(data, pos, mask_id=False)
    if seg is None:
        return False
    seg_size, seg_used = seg
    unknown = seg_size >= (1 << (7 * seg_used)) - 1    # all-ones = streaming/unknown size
    pos += seg_used
    seg_end = len(data) if unknown else pos + seg_size
    if seg_end > len(data):
        return False

    # Walk the Segment's top-level children. Checking only the Segment header is not enough:
    # header-kept encryption preserves the first few KB (EBML header + Segment header), so
    # the chain must be followed past that point, where the ciphertext breaks it.
    children = 0
    while pos < seg_end and children < 256:
        cid = _ebml_vint(data, pos, mask_id=True)
        if cid is None:
            return False
        csize = _ebml_vint(data, pos + cid[1], mask_id=False)
        if csize is None:
            return False
        size_v, size_u = csize
        if size_v >= (1 << (7 * size_u)) - 1:
            return True                                # unknown-size child (streaming): accept
        pos += cid[1] + size_u + size_v
        if pos > seg_end:
            return False
        children += 1
    return True


_MP3_BITRATES_V1_L3 = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0]
_MP3_BITRATES_V2_L3 = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0]
_MP3_RATES = {3: [44100, 48000, 32000], 2: [22050, 24000, 16000], 0: [11025, 12000, 8000]}


def _mp3_structurally_ok(data: bytes, frames_to_check: int = 12) -> bool:
    """After any ID3 tag, frame-sync headers must keep appearing at the computed frame
    lengths. Encrypting the body breaks the chain at the very first hop."""
    pos = 0
    if data[:3] == b"ID3" and len(data) >= 10:         # skip ID3v2 (syncsafe size)
        size = 0
        for b in data[6:10]:
            size = (size << 7) | (b & 0x7F)
        pos = 10 + size
    checked = 0
    while checked < frames_to_check:
        if pos + 4 > len(data):
            return checked > 0                         # ran out cleanly after real frames
        if data[pos] != 0xFF or (data[pos + 1] & 0xE0) != 0xE0:
            return False
        ver = (data[pos + 1] >> 3) & 0x03
        layer = (data[pos + 1] >> 1) & 0x03
        br_i = (data[pos + 2] >> 4) & 0x0F
        sr_i = (data[pos + 2] >> 2) & 0x03
        pad = (data[pos + 2] >> 1) & 0x01
        if ver == 1 or layer == 0 or br_i in (0, 15) or sr_i == 3:
            return False
        table = _MP3_BITRATES_V1_L3 if ver == 3 else _MP3_BITRATES_V2_L3
        bitrate, rate = table[br_i] * 1000, _MP3_RATES[ver][sr_i]
        if not bitrate or not rate:
            return False
        if layer == 3:                                 # Layer I
            length = (12 * bitrate // rate + pad) * 4
        else:                                          # Layer II / III
            length = 144 * bitrate // rate + pad
        if length <= 4:
            return False
        pos += length
        checked += 1
    return True


def _rar_structurally_ok(data: bytes, headers_to_check: int = 8) -> bool:
    """RAR 5 stores a CRC32 in front of every header; RAR 4 a CRC16. Walk the first few
    headers and verify them - encrypting the body breaks the chain immediately."""
    rar5 = b"\x52\x61\x72\x21\x1a\x07\x01\x00"
    rar4 = b"\x52\x61\x72\x21\x1a\x07\x00"

    if data[:8] == rar5:
        pos, checked = 8, 0
        while checked < headers_to_check and pos + 4 < len(data):
            want = int.from_bytes(data[pos:pos + 4], "little")
            val, used = _rar_vint(data, pos + 4)
            if used == 0 or val <= 0:
                return False
            start, end = pos + 4, pos + 4 + used + val
            if end > len(data):
                return False
            if zlib.crc32(data[start:end]) & 0xFFFFFFFF != want:
                return False
            pos, checked = end, checked + 1
        return checked > 0

    if data[:7] == rar4:
        pos, checked = 7, 0
        while checked < headers_to_check and pos + 7 <= len(data):
            want = int.from_bytes(data[pos:pos + 2], "little")
            hsize = int.from_bytes(data[pos + 5:pos + 7], "little")
            if hsize < 7 or pos + hsize > len(data):
                return False
            if (zlib.crc32(data[pos + 2:pos + hsize]) & 0xFFFF) != want:
                return False
            flags = int.from_bytes(data[pos + 3:pos + 5], "little")
            add = 0
            if flags & 0x8000:
                if pos + hsize + 4 > len(data):
                    return False
                add = int.from_bytes(data[pos + 7:pos + 11], "little")
            pos, checked = pos + hsize + add, checked + 1
        return checked > 0

    return False


def _rar_vint(data: bytes, pos: int) -> tuple[int, int]:
    """RAR 5 variable int: 7 bits per byte, little-endian, high bit = continue."""
    value, shift, used = 0, 0, 0
    while pos + used < len(data) and used < 10:
        b = data[pos + used]
        value |= (b & 0x7F) << shift
        used += 1
        if not b & 0x80:
            return value, used
        shift += 7
    return 0, 0


def _sevenzip_structurally_ok(data: bytes) -> bool:
    """7z keeps a CRC32 of its 20-byte start header, which itself holds the offset, size and
    CRC32 of the next header. Both must check out and the next header must fit the file."""
    if data[:6] != b"\x37\x7a\xbc\xaf\x27\x1c" or len(data) < 32:
        return False
    start = data[12:32]                                  # NextHeaderOffset/Size/CRC
    if zlib.crc32(start) & 0xFFFFFFFF != int.from_bytes(data[8:12], "little"):
        return False
    nh_off = int.from_bytes(start[0:8], "little")
    nh_size = int.from_bytes(start[8:16], "little")
    nh_crc = int.from_bytes(start[16:20], "little")
    begin, end = 32 + nh_off, 32 + nh_off + nh_size
    if begin < 32 or end > len(data):
        return False
    if nh_size == 0:                                     # empty archive: nothing more to check
        return True
    return zlib.crc32(data[begin:end]) & 0xFFFFFFFF == nh_crc


def structural_ok(path: Path, magic: bool | None) -> bool | None:
    """
    A deeper check than magic bytes: is the file a STRUCTURALLY valid instance of its type?

    Returns True (verified valid), False (header may be intact but structure is broken), or
    None (no cheap structural check for this type - trust the magic). Bounded by a size cap
    so a huge valid file is trusted on its magic rather than fully parsed. This is what
    catches "header-kept" encryption, which leaves the magic bytes but corrupts the body.
    """
    if magic is False:
        return False            # header already broken; definitely not valid
    if magic is None:
        return None             # no signature for this type (txt/csv/json/...) - nothing to verify
    ext = Path(path).suffix.lower()
    try:
        if path.stat().st_size > config.STRUCT_CHECK_MAX_BYTES:
            return True         # too big to parse live; trust the (valid) magic
        if ext in _ZIP_EXTS:
            if not zipfile.is_zipfile(path):
                return False
            with zipfile.ZipFile(path) as zf:
                return zf.testzip() is None           # None = every member's CRC passed
        if ext == ".png":
            return _png_structurally_ok(path.read_bytes())
        if ext in (".gz", ".gzip", ".tgz"):
            with gzip.open(path, "rb") as gz:
                gz.read(1 << 20)                      # decompresses; raises if corrupt
            return True
        if ext == ".pdf":
            tail = path.read_bytes()[-2048:]
            return b"%%EOF" in tail and (b"startxref" in tail or b"xref" in tail)
        if ext in (".jpg", ".jpeg"):
            data = path.read_bytes()
            return data[:3] == b"\xff\xd8\xff" and data.rstrip(b"\x00")[-2:] == b"\xff\xd9"
        if ext in (".mp4", ".mov", ".m4v", ".m4a"):
            return _mp4_structurally_ok(path.read_bytes())
        if ext in (".mkv", ".webm"):
            return _mkv_structurally_ok(path.read_bytes())
        if ext == ".mp3":
            return _mp3_structurally_ok(path.read_bytes())
        if ext == ".rar":
            return _rar_structurally_ok(path.read_bytes())
        if ext in (".7z", ".7zip"):
            return _sevenzip_structurally_ok(path.read_bytes())
    except Exception:
        return False            # any parse error means the structure is broken
    return True                 # valid magic, no deeper check available -> trust it


def read_windows(
    path: Path | str,
    windows: int,
    window: int = config.ENTROPY_SAMPLE_BYTES,
) -> list[bytes]:
    """
    Read up to `windows` evenly-spaced chunks of `window` bytes across a file.

    Sampling several offsets - not just the first 64 KB - is what catches intermittent /
    partial encryption, where the start of the file is deliberately left untouched. For a
    small file this returns a single chunk (the whole file).
    """
    path = Path(path)
    size = path.stat().st_size
    if windows <= 1 or size <= window:
        return [read_sample(path, window)]

    # Offsets start-of-file ... end-of-file, each the start of one window.
    last_start = max(0, size - window)
    offsets = sorted({int(i * last_start / (windows - 1)) for i in range(windows)})
    chunks: list[bytes] = []
    with open(path, "rb") as handle:
        for off in offsets:
            handle.seek(off)
            data = handle.read(window)
            if data:
                chunks.append(data)
    return chunks or [b""]


def _encoded_check(data: bytes, entropy_val: float) -> bool:
    """is_encoded with the entropy already computed, to avoid recomputing it per window."""
    if len(data) < 64:
        return False
    if not (config.ENCODED_ENTROPY_MIN <= entropy_val <= config.ENCODED_ENTROPY_MAX):
        return False  # cheap numeric gate first, before the O(n) charset scan
    in_alphabet = sum(1 for b in data if b in _BASE64_BYTES) / len(data)
    return in_alphabet >= config.ENCODED_MIN_ALPHABET_FRAC


def is_encoded(data: bytes) -> bool:
    """
    True if `data` looks like base64/encoded text rather than raw bytes or ciphertext.

    Encrypted data base64-encoded has two tells at once: almost every byte is in the base64
    alphabet, and the entropy sits around 6 bits/byte (a 64-symbol alphabet), below the ~8
    of raw ciphertext. Plain English fails the entropy floor; raw ciphertext fails the
    charset test; so the pair is a reasonably specific signature.
    """
    if len(data) < 64:
        return False
    return _encoded_check(data, shannon_entropy(data))


def looks_random(
    data: bytes,
    entropy: float | None = None,
    chi: float | None = None,
) -> bool:
    """
    True if the bytes behave like encrypted/compressed data: high entropy AND a
    near-uniform byte distribution. Both conditions must hold, because either one
    alone is noisier than the pair.
    """
    if not data:
        return False
    entropy = shannon_entropy(data) if entropy is None else entropy
    chi = chi_square(data) if chi is None else chi
    return entropy >= config.HIGH_ENTROPY and chi <= config.CHI_SQUARE_RANDOM_MAX


def analyse_file(
    path: Path | str, max_bytes: int = config.ENTROPY_SAMPLE_BYTES
) -> FileSignals:
    """
    Read a file and return every signal we can derive from its bytes.

    With multi-offset sampling enabled we look at several windows and keep the MOST
    suspicious one (highest entropy) for the entropy/chi/looks-random signals, so partial
    encryption cannot hide in an untouched region. The magic-byte check always uses the
    true start of the file, and the encoded check runs over any sampled window.
    """
    path = Path(path)
    n = config.ENTROPY_WINDOWS if config.FEATURE_MULTI_OFFSET_ENTROPY else 1
    windows = read_windows(path, n, max_bytes)

    # Compute each window's entropy ONCE and reuse it (picking the max, and for the encoded
    # check), instead of recomputing Shannon entropy several times per file.
    entropies = [shannon_entropy(w) for w in windows]
    best_i = max(range(len(windows)), key=entropies.__getitem__)
    best, entropy = windows[best_i], entropies[best_i]
    chi = chi_square(best)
    encoded = config.FEATURE_ENCODED_DETECTION and any(
        _encoded_check(w, h) for w, h in zip(windows, entropies)
    )
    magic = magic_bytes_ok(path, windows[0])
    return FileSignals(
        path=path,
        size=path.stat().st_size,
        ext=path.suffix.lower(),
        entropy=entropy,
        chi_square=chi,
        magic_ok=magic,
        looks_random=looks_random(best, entropy, chi),
        encoded=encoded,
        structural_ok=structural_ok(path, magic),
    )
