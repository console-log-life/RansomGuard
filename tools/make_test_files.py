"""
make_test_files.py

WHAT: builds a fake "user documents" folder inside ./sandbox/protected - text, csv, json,
      a docx, a pdf, a jpg, a png, a zip and an mp4 - that we can safely let the simulator
      attack and then restore.

WHY : the detector must be tested on a realistic mix, not only on text. Already-compressed
      files (jpg/zip/mp4) have entropy ~7.9, which is almost as high as encrypted data.
      They are in the corpus on purpose: they are the hard cases that prove why entropy
      alone is not a detector, and why magic bytes + canaries + process behaviour matter.

The generator is seeded, so every run produces byte-identical files and our measured
numbers are reproducible.

Run:  python tools/make_test_files.py            # default sandbox path
      python tools/make_test_files.py --clean --scale 3
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import shutil
import sys
import zipfile
from pathlib import Path

# Allow "python tools/make_test_files.py" without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ransomguard import config  # noqa: E402

WORDS = (
    "network cipher packet entropy padding session integrity message digest random "
    "protocol signature exchange handshake secret rotation audit incident response "
    "backup restore manifest attestation recovery archive inventory invoice ledger"
).split()


def paragraph(rng: random.Random, sentences: int = 6) -> str:
    """A few sentences of plausible English-ish prose (entropy ~4.2 bits/byte)."""
    out = []
    for _ in range(sentences):
        words = rng.choices(WORDS, k=rng.randint(8, 18))
        out.append(words[0].capitalize() + " " + " ".join(words[1:]) + ".")
    return " ".join(out)


def write_text(path: Path, rng: random.Random, paragraphs: int = 8) -> None:
    body = "\n\n".join(paragraph(rng) for _ in range(paragraphs))
    path.write_text(body + "\n", encoding="utf-8")


def write_csv(path: Path, rng: random.Random, rows: int = 300) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["id", "name", "department", "amount", "status"])
        for i in range(1, rows + 1):
            writer.writerow(
                [
                    i,
                    rng.choice(WORDS).capitalize() + " " + rng.choice(WORDS).capitalize(),
                    rng.choice(["finance", "research", "admin", "it"]),
                    f"{rng.uniform(100, 99999):.2f}",
                    rng.choice(["paid", "pending", "review"]),
                ]
            )


def write_json(path: Path, rng: random.Random, records: int = 120) -> None:
    payload = {
        "version": 3,
        "generated_by": "make_test_files",
        "records": [
            {
                "id": i,
                "label": rng.choice(WORDS),
                "value": round(rng.uniform(0, 1), 6),
                "tags": rng.sample(WORDS, 3),
            }
            for i in range(records)
        ],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_pdf(path: Path, rng: random.Random) -> None:
    """A minimal but structurally real PDF: the point is the "%PDF" header."""
    text = paragraph(rng, sentences=4).replace("(", "").replace(")", "")
    body = (
        "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
        "3 0 obj << /Type /Page /Parent 2 0 R /Contents 4 0 R >> endobj\n"
        f"4 0 obj << /Length {len(text) + 40} >> stream\n"
        f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET\n"
        "endstream endobj\n"
    )
    path.write_bytes(b"%PDF-1.4\n" + body.encode("latin-1") + b"trailer << /Root 1 0 R >>\n%%EOF\n")


def write_docx(path: Path, rng: random.Random) -> None:
    """A .docx is just a ZIP of XML, so we build a tiny real one (header PK\\x03\\x04)."""
    document = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        "<w:body>"
        + "".join(f"<w:p><w:r><w:t>{paragraph(rng, 3)}</w:t></w:r></w:p>" for _ in range(6))
        + "</w:body></w:document>"
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="xml" ContentType="application/xml"/>'
        "</Types>"
    )
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("word/document.xml", document)


def write_zip(path: Path, rng: random.Random, members: int = 5) -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(members):
            zf.writestr(f"notes_{i}.txt", paragraph(rng, 10))


def write_jpg(path: Path, size: int = 120_000) -> None:
    """JFIF header + random payload + end marker.

    The payload is random so the entropy is ~7.99, exactly like real JPEG data. This is
    the file that makes a naive entropy-only detector cry false positive.
    """
    header = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    path.write_bytes(header + os.urandom(size) + b"\xff\xd9")


def write_png(path: Path, size: int = 60_000) -> None:
    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = b"\x00\x00\x00\rIHDR" + b"\x00\x00\x02\x00\x00\x00\x02\x00\x08\x06\x00\x00\x00"
    path.write_bytes(signature + ihdr + os.urandom(size))


def write_mp4(path: Path, size: int = 200_000) -> None:
    """ISO base media: 4-byte box size, then the literal box type "ftyp" at offset 4."""
    ftyp = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2mp41"
    path.write_bytes(ftyp + os.urandom(size))


def build_corpus(root: Path, scale: int, seed: int) -> list[Path]:
    """Create the corpus under `root` and return the list of files written."""
    rng = random.Random(seed)
    created: list[Path] = []

    def make(relative: str, builder) -> None:
        target = config.ensure_inside(root / relative, root)
        target.parent.mkdir(parents=True, exist_ok=True)
        builder(target)
        created.append(target)

    make("readme.txt", lambda p: write_text(p, rng, paragraphs=3))

    for i in range(scale):
        suffix = "" if i == 0 else f"_{i + 1}"
        make(f"documents/notes{suffix}.txt", lambda p: write_text(p, rng))
        make(f"documents/essay{suffix}.txt", lambda p: write_text(p, rng, paragraphs=14))
        make(f"documents/report{suffix}.pdf", lambda p: write_pdf(p, rng))
        make(f"documents/thesis{suffix}.docx", lambda p: write_docx(p, rng))
        make(f"data/records{suffix}.csv", lambda p: write_csv(p, rng))
        make(f"data/inventory{suffix}.csv", lambda p: write_csv(p, rng, rows=800))
        make(f"data/settings{suffix}.json", lambda p: write_json(p, rng))
        make(f"media/photo{suffix}.jpg", write_jpg)
        make(f"media/logo{suffix}.png", write_png)
        make(f"media/clip{suffix}.mp4", write_mp4)
        make(f"archives/project{suffix}.zip", lambda p: write_zip(p, rng))

    return created


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a safe test corpus.")
    parser.add_argument(
        "--path", default=str(config.PROTECTED_DIR), help="target folder (must be in ./sandbox)"
    )
    parser.add_argument("--scale", type=int, default=1, help="repeat the file set N times")
    parser.add_argument("--seed", type=int, default=1234, help="RNG seed (reproducibility)")
    parser.add_argument("--clean", action="store_true", help="delete the folder first")
    args = parser.parse_args(argv)

    # Safety: refuse any target outside ./sandbox, even if the user typed it.
    try:
        root = config.ensure_inside(Path(args.path))
    except config.SandboxViolation as exc:
        print(f"refused: {exc}")
        return 2

    if args.clean and root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)

    created = build_corpus(root, max(1, args.scale), args.seed)
    total = sum(p.stat().st_size for p in created)
    print(f"created {len(created)} files ({total / 1024:.0f} KB) in {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
