"""
test_dataset.py

WHAT: tests the labeled-dataset builder - that variants are labelled correctly, produce the
      right kind of bytes, and that the tuning/test split never leaks a source file across
      both sides.

WHY : the whole file-level evaluation rests on this dataset. If a source file's original
      landed in tuning and its encrypted twin in test, the reported precision/recall would
      be optimistic nonsense; and a mislabelled variant would silently corrupt every metric.
      These run on a tiny synthetic sample (no network, no real download).
"""

from __future__ import annotations

import csv

import pytest

from evaluation import build_dataset as bd
from simulator import container


@pytest.fixture
def tiny_sample(tmp_path, monkeypatch):
    sample = tmp_path / "napierone_sample"
    labeled = tmp_path / "labeled"
    (sample / "TXT").mkdir(parents=True)
    (sample / "JPG").mkdir(parents=True)
    files = [
        ("TXT/a.txt", b"hello world " * 200, "TXT"),
        ("TXT/b.txt", b"the lazy dog " * 300, "TXT"),
        ("JPG/c.jpg", b"\xff\xd8\xff\xe0" + bytes(range(256)) * 300, "JPG"),
    ]
    for rel, data, _ in files:
        (sample / rel).write_bytes(data)
    with (sample / "manifest.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["path", "type", "size", "sha256"])
        w.writeheader()
        for rel, data, typ in files:
            w.writerow({"path": rel, "type": typ, "size": len(data), "sha256": "x"})

    monkeypatch.setattr(bd, "SAMPLE_DIR", sample)
    monkeypatch.setattr(bd, "LABELED_DIR", labeled)
    return sample, labeled


def test_labels_match_variants(tiny_sample):
    rows = bd.build(seed=1234, tuning_frac=0.3)
    for r in rows:
        expected = 0 if r["variant"] in bd.BENIGN else 1
        assert r["label"] == expected
    # every source file produced all 6 variants
    assert len(rows) == 3 * (len(bd.BENIGN) + len(bd.RANSOM))


def test_split_never_leaks_a_source_file(tiny_sample):
    rows = bd.build(seed=1234, tuning_frac=0.3)
    split_by_source: dict[str, set[str]] = {}
    for r in rows:
        split_by_source.setdefault(r["source_file"], set()).add(r["split"])
    # each source file must appear on exactly ONE side of the split
    assert all(len(sides) == 1 for sides in split_by_source.values())


def test_encrypted_variants_are_containers_benign_are_not(tiny_sample):
    _, labeled = tiny_sample
    bd.build(seed=1234, tuning_frac=0.3)
    rows = list(csv.DictReader((labeled / "labels.csv").open(encoding="utf-8")))

    def read(variant: str) -> bytes:
        r = next(r for r in rows if r["variant"] == variant)
        return (labeled / r["path"]).read_bytes()

    assert container.is_container(read("enc_full")[: len(container.MAGIC)])
    assert container.is_container(read("enc_base64")[: len(container.MAGIC)])
    assert container.is_container(read("enc_intermittent")[: len(container.MAGIC)])
    # benign variants are NOT our container; the zip keeps a real PK header
    assert not container.is_container(read("original")[: len(container.MAGIC)])
    assert read("benign_zip")[:2] == b"PK"
    assert read("benign_gzip")[:2] == b"\x1f\x8b"


def test_dataset_is_reproducible(tiny_sample):
    a = bd.build(seed=99, tuning_frac=0.3)
    b = bd.build(seed=99, tuning_frac=0.3)
    assert {r["source_file"]: r["split"] for r in a} == {r["source_file"]: r["split"] for r in b}
