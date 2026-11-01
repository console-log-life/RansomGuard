"""
build_dataset.py

WHAT: turns the real NapierOne sample (datasets/napierone_sample/) into a LABELED file-level
      data set (datasets/labeled/ + labels.csv) for evaluating the detector as a classifier.

WHY : to measure precision/recall/FPR we need files with ground-truth labels. For each
      source file we produce:
        label 0 (benign): the original file, plus two HARD negatives - a ZIP and a GZIP of
                          the original (high-entropy but perfectly legitimate: the case that
                          makes an entropy-only detector cry wolf);
        label 1 (ransomware-encrypted): the simulator's own transforms on a COPY - full
                          AES-256-GCM, intermittent (every other block), and base64 of the
                          ciphertext.
      Reusing the simulator's container functions means we test against exactly what the
      real attacker would write. Nothing here touches the sandbox; all output is under
      datasets/ (git-ignored).

SPLIT: 30% tuning / 70% test, assigned BY SOURCE FILE (seeded), so every variant of one
source file stays on the same side - a classifier can never see a file's original in
tuning and its encrypted twin in test.

Run:  python evaluation/build_dataset.py            # after tools/fetch_napierone.py
      python evaluation/build_dataset.py --seed 7 --tuning-frac 0.3
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import random
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ransomguard import config  # noqa: E402
from simulator import container  # noqa: E402

SAMPLE_DIR = config.PROJECT_ROOT / "datasets" / "napierone_sample"
LABELED_DIR = config.PROJECT_ROOT / "datasets" / "labeled"

# Benign (0) and ransomware (1) variants.
BENIGN = ["original", "benign_zip", "benign_gzip"]
RANSOM = ["enc_full", "enc_intermittent", "enc_base64", "enc_header_kept"]


def _key(seed: int) -> bytes:
    """A fixed 32-byte AES key derived from the seed, so the dataset is reproducible."""
    return hashlib.sha256(f"ransomguard-dataset-{seed}".encode()).digest()


def _benign_zip(data: bytes, name: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(name, data)
    return buf.getvalue()


def _benign_gzip(data: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(data)
    return buf.getvalue()


def _enc_full(data: bytes, key: bytes, name: str) -> bytes:
    return container.pack(name, container.MODE_FULL,
                          [container.encrypt_segment(data, key, name, 0, b64=False)])


def _enc_base64(data: bytes, key: bytes, name: str) -> bytes:
    return container.pack(name, container.MODE_BASE64,
                          [container.encrypt_segment(data, key, name, 0, b64=True)])


def _enc_intermittent(data: bytes, key: bytes, name: str) -> bytes:
    block = config.ENTROPY_SAMPLE_BYTES
    blocks = [data[i:i + block] for i in range(0, max(len(data), 1), block)]
    segs = []
    for i, b in enumerate(blocks):
        if len(blocks) == 1 or i % 2 == 1:       # skip block 0 when there are several
            segs.append(container.encrypt_segment(b, key, name, i, b64=False))
        else:
            segs.append((container.SEG_PLAIN, b))
    return container.pack(name, container.MODE_INTERMITTENT, segs)


def _variant_bytes(variant: str, data: bytes, key: bytes, name: str) -> tuple[bytes, str]:
    """Return (bytes, filename) for a variant. Encrypted variants keep the original name
    (so the magic-byte signal sees a broken header under the real extension)."""
    if variant == "original":
        return data, name
    if variant == "benign_zip":
        return _benign_zip(data, name), name + ".zip"
    if variant == "benign_gzip":
        return _benign_gzip(data), name + ".gz"
    if variant == "enc_full":
        return _enc_full(data, key, name), name
    if variant == "enc_base64":
        return _enc_base64(data, key, name), name
    if variant == "enc_intermittent":
        return _enc_intermittent(data, key, name), name
    if variant == "enc_header_kept":
        # Keep the original header in the clear, encrypt the body - the magic bytes survive.
        return container.make_header_kept(data, key, name), name
    raise ValueError(variant)


def build(seed: int, tuning_frac: float) -> list[dict]:
    manifest = SAMPLE_DIR / "manifest.csv"
    if not manifest.exists():
        raise SystemExit(f"no sample at {manifest} - run tools/fetch_napierone.py first")

    sources = list(csv.DictReader(manifest.open(encoding="utf-8")))
    rng = random.Random(seed)
    key = _key(seed)

    # Assign each SOURCE FILE to a split up front, so all its variants travel together.
    split_of: dict[str, str] = {}
    for row in sources:
        split_of[row["path"]] = "tuning" if rng.random() < tuning_frac else "test"

    if LABELED_DIR.exists():
        import shutil
        shutil.rmtree(LABELED_DIR)
    LABELED_DIR.mkdir(parents=True, exist_ok=True)

    rows: list[dict] = []
    for row in sources:
        src_rel = row["path"]
        src_type = row["type"]
        data = (SAMPLE_DIR / src_rel).read_bytes()
        name = Path(src_rel).name
        split = split_of[src_rel]
        for variant in BENIGN + RANSOM:
            payload, fname = _variant_bytes(variant, data, key, name)
            out = LABELED_DIR / src_type / variant / fname
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(payload)
            rows.append({
                "path": str(out.relative_to(LABELED_DIR)).replace("\\", "/"),
                "source_file": src_rel,
                "source_type": src_type,
                "variant": variant,
                "label": 0 if variant in BENIGN else 1,
                "split": split,
            })

    labels = LABELED_DIR / "labels.csv"
    with labels.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["path", "source_file", "source_type", "variant", "label", "split"])
        writer.writeheader()
        writer.writerows(rows)
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a labeled file-level dataset from the NapierOne sample.")
    parser.add_argument("--seed", type=int, default=1234)
    parser.add_argument("--tuning-frac", type=float, default=0.3)
    args = parser.parse_args(argv)

    rows = build(args.seed, args.tuning_frac)
    n0 = sum(1 for r in rows if r["label"] == 0)
    n1 = sum(1 for r in rows if r["label"] == 1)
    srcs = {r["source_file"] for r in rows}
    tun_src = {r["source_file"] for r in rows if r["split"] == "tuning"}
    print(f"built {len(rows)} labeled samples from {len(srcs)} source files "
          f"({len(tun_src)} tuning / {len(srcs) - len(tun_src)} test source files)")
    print(f"  benign (0): {n0}   ransomware (1): {n1}")
    for split in ("tuning", "test"):
        s = [r for r in rows if r["split"] == split]
        print(f"  {split:7}: {len(s)} samples ({sum(1 for r in s if r['label']==1)} ransomware)")
    print(f"  -> {LABELED_DIR / 'labels.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
