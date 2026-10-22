"""
container.py

WHAT: the on-disk format the simulator writes for an encrypted file, and the logic to
      rebuild the original from it. One format covers every attack mode (full, intermittent,
      no-rename, base64), so a single undo routine reverses them all.

WHY : the brief requires smarter attacks that are STILL fully reversible from the saved key.
      Different modes transform the file differently (whole-file, block-wise, base64), so we
      need a self-describing container that records exactly how to put the file back
      together. Every encrypted chunk is AES-256-GCM, with the original name and the chunk's
      position bound in as associated data, so a wrong key or any tampering fails loudly
      instead of producing garbage.

Layout (all big-endian):
    MAGIC b"RGSIM1" | mode(1) | name_len(2) | original_name
    num_segments(4) | repeated: seg_type(1) | length(4) | data
      seg_type 0 = PLAINTEXT  : data is the original bytes of this segment (left as-is)
      seg_type 1 = AESGCM     : data is nonce(12) + ciphertext+tag
      seg_type 2 = AESGCM_B64 : data is base64(nonce + ciphertext+tag)  (low-entropy variant)
Rebuilding concatenates each segment's plaintext in order.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"RGSIM1"
NONCE_SIZE = 12

# Attack modes (stored in the mode byte, for information / undo reporting).
MODE_FULL = 0
MODE_INTERMITTENT = 1
MODE_NO_RENAME = 2
MODE_BASE64 = 3

SEG_PLAIN = 0
SEG_ENC = 1
SEG_ENC_B64 = 2


def _aad(name: str, index: int) -> bytes:
    """Associated data for a segment: binds the original name and the segment's position."""
    return f"{name}|{index}".encode("utf-8")


def encrypt_segment(plaintext: bytes, key: bytes, name: str, index: int, b64: bool) -> tuple[int, bytes]:
    """Encrypt one chunk; return (seg_type, data) for the container."""
    import os

    nonce = os.urandom(NONCE_SIZE)
    ct = AESGCM(key).encrypt(nonce, plaintext, _aad(name, index))
    blob = nonce + ct
    if b64:
        return SEG_ENC_B64, base64.b64encode(blob)
    return SEG_ENC, blob


def pack(original_name: str, mode: int, segments: list[tuple[int, bytes]]) -> bytes:
    """Serialize a container from a list of (seg_type, data) segments."""
    out = bytearray()
    out += MAGIC
    out += bytes([mode])
    name = original_name.encode("utf-8")
    out += len(name).to_bytes(2, "big")
    out += name
    out += len(segments).to_bytes(4, "big")
    for seg_type, data in segments:
        out += bytes([seg_type])
        out += len(data).to_bytes(4, "big")
        out += data
    return bytes(out)


def is_container(blob: bytes) -> bool:
    """True if these bytes start with our container magic (so undo can find in-place ones)."""
    return blob[: len(MAGIC)] == MAGIC


def rebuild(blob: bytes, key: bytes) -> tuple[str, bytes]:
    """
    Parse a container and return (original_name, original_plaintext).

    Raises cryptography.exceptions.InvalidTag (via AESGCM.decrypt) if the key is wrong or
    the data was tampered with - so a failed undo is never silent.
    """
    if not is_container(blob):
        raise ValueError("not a RansomGuard-sim container")
    pos = len(MAGIC)
    pos += 1  # mode byte (not needed to rebuild)
    name_len = int.from_bytes(blob[pos:pos + 2], "big"); pos += 2
    name = blob[pos:pos + name_len].decode("utf-8"); pos += name_len
    num = int.from_bytes(blob[pos:pos + 4], "big"); pos += 4

    chunks: list[bytes] = []
    for index in range(num):
        seg_type = blob[pos]; pos += 1
        length = int.from_bytes(blob[pos:pos + 4], "big"); pos += 4
        data = blob[pos:pos + length]; pos += length
        if seg_type == SEG_PLAIN:
            chunks.append(data)
        else:
            raw = base64.b64decode(data) if seg_type == SEG_ENC_B64 else data
            nonce, ct = raw[:NONCE_SIZE], raw[NONCE_SIZE:]
            chunks.append(AESGCM(key).decrypt(nonce, ct, _aad(name, index)))
    return name, b"".join(chunks)
