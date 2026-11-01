"""
fetch_napierone.py

WHAT: downloads a small, stratified sample of REAL files from the public NapierOne data set
      (hosted unsigned on s3://napierone.com), into datasets/napierone_sample/ with a
      manifest. No AWS account is needed; access is anonymous (UNSIGNED).

WHY : the detector was only ever tested on a 16-file synthetic corpus. A credible evaluation
      needs real files with realistic entropy profiles - genuine JP/PNG/MP3 (high entropy,
      benign hard-negatives) and real PDF/DOCX/XLSX/TXT/CSV/JSON/HTML documents. NapierOne
      (Davies et al., 2022) is a modern mixed-file data set built for exactly this.

LAYOUT NOTE: NapierOne does not store individual files on S3; each type folder holds large
ZIP *bundles* (e.g. NapierOne/Data/JPG/JPG-q001-tiny.zip), and the individual files live
inside. So for each requested type we download the SMALLEST bundle, then extract a seeded
random sample of its members (skipping any over --max-file-mb). Bundles larger than
--max-archive-mb are skipped (the already-compressed types - ZIP/RAR/7ZIP/GZIP/MP4/MKV -
have 160-625 MB bundles); raise the cap to include them.

Everything lands under datasets/ which is git-ignored (large, regenerable, not ours to
redistribute). Nothing here touches the sandbox.

Run:  python tools/fetch_napierone.py                       # defaults: 40/type, <=100 MB bundles
      python tools/fetch_napierone.py --count 40 --max-archive-mb 700   # include heavy types
      python tools/fetch_napierone.py --types JPG,PNG,PDF,TXT
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import random
import sys
import zipfile
from pathlib import Path

import boto3
from botocore import UNSIGNED
from botocore.config import Config

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ransomguard import config  # noqa: E402  (only for PROJECT_ROOT)

BUCKET = "napierone.com"
DATA_PREFIX = "NapierOne/Data/"
DEFAULT_TYPES = [
    "ZIP", "RAR", "7ZIP", "GZIP", "JPG", "PNG", "MP4", "MKV", "MP3",   # high-entropy
    "PDF", "DOCX", "XLSX", "PPTX", "TXT", "CSV", "JSON", "HTML",       # documents
]
# Expected member extension(s) per type folder, so we skip stray readmes/hash files.
EXT_MAP: dict[str, set[str]] = {
    "ZIP": {"zip"}, "RAR": {"rar"}, "7ZIP": {"7z"}, "GZIP": {"gz", "gzip", "tgz"},
    "JPG": {"jpg", "jpeg"}, "PNG": {"png"}, "MP4": {"mp4"}, "MKV": {"mkv"}, "MP3": {"mp3"},
    "PDF": {"pdf"}, "DOCX": {"docx"}, "XLSX": {"xlsx"}, "PPTX": {"pptx"},
    "TXT": {"txt"}, "CSV": {"csv"}, "JSON": {"json"}, "HTML": {"html", "htm"},
}

# For types with several bundle variants, prefer a REPRESENTATIVE one over the merely
# smallest. JPG's smallest bundle is q001 (ultra-low quality -> low entropy, unrealistic);
# real web photos ("from-web") or a normal quality (q075-q090) are the right high-entropy
# hard-negative. We pick the smallest bundle (under the cap) whose name matches a pattern.
PREFER: dict[str, tuple[str, ...]] = {
    "JPG": ("from-web", "q090", "q080", "q075"),
}

OUT_DIR = config.PROJECT_ROOT / "datasets" / "napierone_sample"


def _client():
    return boto3.client(
        "s3", region_name="us-east-1",
        config=Config(signature_version=UNSIGNED, s3={"addressing_style": "path"}),
    )


def _pick_bundle(s3, type_name: str, max_archive_bytes: int) -> tuple[str, int] | None:
    """Pick the bundle to download: the smallest .zip UNDER the cap, preferring a
    representative variant (see PREFER). None if nothing qualifies."""
    paginator = s3.get_paginator("list_objects_v2")
    bundles: list[tuple[str, int]] = []
    for page in paginator.paginate(Bucket=BUCKET, Prefix=f"{DATA_PREFIX}{type_name}/"):
        for obj in page.get("Contents", []):
            if obj["Key"].lower().endswith(".zip") and obj["Size"] <= max_archive_bytes:
                bundles.append((obj["Key"], obj["Size"]))
    if not bundles:
        return None
    patterns = PREFER.get(type_name, ())
    preferred = [b for b in bundles if any(p in b[0].lower() for p in patterns)]
    pool = preferred or bundles
    return min(pool, key=lambda b: b[1])


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch_type(s3, type_name: str, count: int, rng: random.Random,
               max_archive_bytes: int, max_file_bytes: int,
               out_dir: Path, cache_dir: Path, keep_archive: bool) -> list[dict]:
    """Download the smallest bundle for one type and extract up to `count` sample members."""
    bundle = _pick_bundle(s3, type_name, max_archive_bytes)
    if bundle is None:
        print(f"  {type_name:6} skipped: no .zip bundle under cap {max_archive_bytes/1e6:.0f} MB")
        return []
    key, size = bundle

    cache_dir.mkdir(parents=True, exist_ok=True)
    local_zip = cache_dir / key.split("/")[-1]
    if not local_zip.exists():
        s3.download_file(BUCKET, key, str(local_zip))

    exts = EXT_MAP.get(type_name, set())
    rows: list[dict] = []
    type_out = out_dir / type_name
    type_out.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(local_zip) as zf:
        members = [
            m for m in zf.infolist()
            if not m.is_dir() and m.file_size <= max_file_bytes
            and (not exts or m.filename.rsplit(".", 1)[-1].lower() in exts)
        ]
        rng.shuffle(members)
        for m in members[:count]:
            data = zf.read(m)
            base = Path(m.filename).name
            dest = type_out / base
            dest.write_bytes(data)
            rows.append({
                "path": str(dest.relative_to(out_dir)).replace("\\", "/"),
                "type": type_name, "size": len(data), "sha256": _sha256(data),
            })
    if not keep_archive:
        local_zip.unlink(missing_ok=True)
    print(f"  {type_name:6} {len(rows):3} files from {key.split('/')[-1]} ({size/1e6:.0f} MB bundle)")
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fetch a stratified NapierOne sample (unsigned S3).")
    parser.add_argument("--count", type=int, default=40, help="files per type (default 40)")
    parser.add_argument("--seed", type=int, default=1234, help="RNG seed (reproducible sample)")
    parser.add_argument("--max-archive-mb", type=float, default=100.0,
                        help="skip type bundles larger than this (default 100)")
    parser.add_argument("--max-file-mb", type=float, default=5.0,
                        help="skip extracted files larger than this (default 5)")
    parser.add_argument("--types", default=",".join(DEFAULT_TYPES),
                        help="comma-separated NapierOne type folders")
    parser.add_argument("--out", default=str(OUT_DIR))
    parser.add_argument("--keep-archives", action="store_true", help="keep the downloaded bundles")
    args = parser.parse_args(argv)

    out_dir = Path(args.out)
    cache_dir = out_dir.parent / ".cache"
    rng = random.Random(args.seed)
    types = [t.strip().upper() for t in args.types.split(",") if t.strip()]
    s3 = _client()

    print(f"fetching <= {args.count} files/type into {out_dir} "
          f"(bundle cap {args.max_archive_mb:.0f} MB, file cap {args.max_file_mb:.0f} MB)")
    all_rows: list[dict] = []
    for t in types:
        all_rows += fetch_type(
            s3, t, args.count, rng,
            int(args.max_archive_mb * 1024 * 1024), int(args.max_file_mb * 1024 * 1024),
            out_dir, cache_dir, args.keep_archives,
        )

    manifest = out_dir / "manifest.csv"
    out_dir.mkdir(parents=True, exist_ok=True)
    with manifest.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["path", "type", "size", "sha256"])
        writer.writeheader()
        writer.writerows(all_rows)

    by_type: dict[str, int] = {}
    for r in all_rows:
        by_type[r["type"]] = by_type.get(r["type"], 0) + 1
    print(f"\nTOTAL {len(all_rows)} files across {len(by_type)} types -> {manifest}")
    for t in types:
        print(f"  {t:6} {by_type.get(t, 0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
