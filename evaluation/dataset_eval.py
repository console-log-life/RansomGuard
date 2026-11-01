"""
dataset_eval.py

WHAT: evaluates the detector as a FILE-LEVEL classifier on the labeled NapierOne dataset.
      For every sample it runs entropy.analyse_file and the file-level part of the scorer
      (evaluate_signals vs the clean original as baseline) to get a combined suspicion score,
      tunes the decision threshold on the TUNING split only, and reports metrics on the TEST
      split: precision/recall/F1/FPR/accuracy + confusion matrix, per-type and per-variant
      breakdowns, ROC+AUC for entropy-only vs the combined score, and old vs new detector.

WHY : the honest way to answer "does it actually work, and do the Part-B upgrades help?" on
      real files - with a proper train/test split so the numbers are not self-fulfilling.
      It needs no sklearn; ROC/AUC are computed directly.

Run:  python evaluation/build_dataset.py        # once, to create datasets/labeled/
      python evaluation/dataset_eval.py
"""

from __future__ import annotations

import csv
import sys
from dataclasses import dataclass
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ransomguard import config, entropy  # noqa: E402
from ransomguard.baseline import BaselineEntry  # noqa: E402
from ransomguard.scorer import evaluate_signals  # noqa: E402

LABELED_DIR = config.PROJECT_ROOT / "datasets" / "labeled"


@dataclass
class Scored:
    path: str
    label: int
    source_type: str
    variant: str
    split: str
    entropy: float
    score: int


def _baseline_of(signals) -> BaselineEntry:
    return BaselineEntry(entropy=signals.entropy, sha256="", size=signals.size, ext=signals.ext)


def analyse_all(rows: list[dict], multi_offset: bool, encoded: bool) -> list[Scored]:
    """Score every sample under a given feature configuration (old vs new detector)."""
    saved = (config.FEATURE_MULTI_OFFSET_ENTROPY, config.FEATURE_ENCODED_DETECTION)
    config.FEATURE_MULTI_OFFSET_ENTROPY, config.FEATURE_ENCODED_DETECTION = multi_offset, encoded
    try:
        # One baseline per source file: analyse its clean 'original' variant.
        originals = {r["source_file"]: r for r in rows if r["variant"] == "original"}
        base_cache: dict[str, BaselineEntry] = {}
        for src, r in originals.items():
            base_cache[src] = _baseline_of(entropy.analyse_file(LABELED_DIR / r["path"]))

        out: list[Scored] = []
        for r in rows:
            sig = entropy.analyse_file(LABELED_DIR / r["path"])
            base = base_cache.get(r["source_file"])
            reasons = evaluate_signals(sig, base, canary_touched=False)
            out.append(Scored(
                path=r["path"], label=int(r["label"]), source_type=r["source_type"],
                variant=r["variant"], split=r["split"], entropy=sig.entropy,
                score=sum(x.points for x in reasons),
            ))
        return out
    finally:
        config.FEATURE_MULTI_OFFSET_ENTROPY, config.FEATURE_ENCODED_DETECTION = saved


# --------------------------------------------------------------------- metrics
def confusion(scored: list[Scored], threshold: float, key=lambda s: s.score) -> tuple[int, int, int, int]:
    tp = fp = tn = fn = 0
    for s in scored:
        pred = 1 if key(s) >= threshold else 0
        if s.label == 1 and pred == 1: tp += 1
        elif s.label == 0 and pred == 1: fp += 1
        elif s.label == 0 and pred == 0: tn += 1
        else: fn += 1
    return tp, fp, tn, fn


def metrics(tp: int, fp: int, tn: int, fn: int) -> dict[str, float]:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    acc = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) else 0.0
    return {"precision": p, "recall": r, "f1": f1, "fpr": fpr, "accuracy": acc}


def tune_threshold(scored: list[Scored], key=lambda s: s.score) -> float:
    """Pick the threshold maximising F1 on the given (tuning) samples."""
    cands = sorted({key(s) for s in scored})
    best_t, best_f1 = cands[0] if cands else 0.0, -1.0
    for t in cands:
        m = metrics(*confusion(scored, t, key))
        if m["f1"] > best_f1:
            best_f1, best_t = m["f1"], t
    return best_t


def roc_auc(scored: list[Scored], key=lambda s: s.score) -> tuple[list[float], list[float], float]:
    """ROC points (fpr, tpr) by threshold sweep + AUC (rank / Mann-Whitney)."""
    pos = [key(s) for s in scored if s.label == 1]
    neg = [key(s) for s in scored if s.label == 0]
    npos, nneg = len(pos), len(neg)
    thresholds = sorted({key(s) for s in scored} | {min(pos + neg) - 1, max(pos + neg) + 1}, reverse=True)
    fprs, tprs = [], []
    for t in thresholds:
        tp = sum(1 for v in pos if v >= t); fp = sum(1 for v in neg if v >= t)
        tprs.append(tp / npos if npos else 0.0)
        fprs.append(fp / nneg if nneg else 0.0)
    # AUC via rank statistic (robust to ties).
    allv = sorted([(v, 1) for v in pos] + [(v, 0) for v in neg])
    ranks = {}
    i = 0
    while i < len(allv):
        j = i
        while j < len(allv) and allv[j][0] == allv[i][0]:
            j += 1
        avg = (i + 1 + j) / 2.0
        for k in range(i, j):
            ranks[k] = avg
        i = j
    rank_sum = sum(ranks[idx] for idx, (_, lbl) in enumerate(allv) if lbl == 1)
    auc = (rank_sum - npos * (npos + 1) / 2) / (npos * nneg) if npos and nneg else 0.0
    return fprs, tprs, auc


# --------------------------------------------------------------------- report
def _md_metrics(name: str, m: dict[str, float], cm: tuple[int, int, int, int]) -> list[str]:
    tp, fp, tn, fn = cm
    return [
        f"**{name}**  precision={m['precision']:.3f} recall={m['recall']:.3f} "
        f"F1={m['f1']:.3f} FPR={m['fpr']:.3f} accuracy={m['accuracy']:.3f}",
        f"  confusion: TP={tp} FP={fp} TN={tn} FN={fn}",
    ]


def _per_group(test: list[Scored], threshold: float, attr: str) -> list[str]:
    groups: dict[str, list[Scored]] = {}
    for s in test:
        groups.setdefault(getattr(s, attr), []).append(s)
    lines = [f"| {attr} | n | recall (ransomware) | FPR (benign) |", "|---|---|---|---|"]
    for g in sorted(groups):
        gs = groups[g]
        ransom = [s for s in gs if s.label == 1]
        benign = [s for s in gs if s.label == 0]
        rec = sum(1 for s in ransom if s.score >= threshold) / len(ransom) if ransom else float("nan")
        fpr = sum(1 for s in benign if s.score >= threshold) / len(benign) if benign else float("nan")
        rec_s = "-" if ransom == [] else f"{rec:.3f}"
        fpr_s = "-" if benign == [] else f"{fpr:.3f}"
        lines.append(f"| {g} | {len(gs)} | {rec_s} | {fpr_s} |")
    return lines


def chart_confusion(cm, out: Path) -> None:
    tp, fp, tn, fn = cm
    fig, ax = plt.subplots(figsize=(3.6, 3.4))
    grid = [[tn, fp], [fn, tp]]
    ax.imshow(grid, cmap="Blues")
    for (i, j), v in [((0, 0), tn), ((0, 1), fp), ((1, 0), fn), ((1, 1), tp)]:
        ax.text(j, i, str(v), ha="center", va="center", fontsize=14)
    ax.set_xticks([0, 1]); ax.set_xticklabels(["pred benign", "pred ransom"])
    ax.set_yticks([0, 1]); ax.set_yticklabels(["true benign", "true ransom"])
    ax.set_title("Confusion (new, test)")
    fig.tight_layout(); fig.savefig(out, dpi=120); plt.close(fig)


def chart_roc(curves: dict[str, tuple[list[float], list[float], float]], out: Path) -> None:
    fig, ax = plt.subplots(figsize=(5, 4.5))
    for label, (fpr, tpr, auc) in curves.items():
        pts = sorted(zip(fpr, tpr))
        ax.plot([p[0] for p in pts], [p[1] for p in pts], marker=".", label=f"{label} (AUC={auc:.3f})")
    ax.plot([0, 1], [0, 1], "--", color="#999", linewidth=1)
    ax.set_xlabel("false-positive rate"); ax.set_ylabel("true-positive rate")
    ax.set_title("ROC (test): entropy-only vs combined"); ax.legend(loc="lower right", fontsize=8)
    fig.tight_layout(); fig.savefig(out, dpi=120); plt.close(fig)


def chart_per_type_fpr(test: list[Scored], threshold: float, out: Path) -> None:
    types: dict[str, list[Scored]] = {}
    for s in test:
        if s.label == 0:
            types.setdefault(s.source_type, []).append(s)
    labels = sorted(types)
    fprs = [sum(1 for s in types[t] if s.score >= threshold) / len(types[t]) for t in labels]
    fig, ax = plt.subplots(figsize=(8, 3.8))
    ax.bar(labels, fprs, color="#e67e22")
    ax.set_ylabel("false-positive rate"); ax.set_ylim(0, 1)
    ax.set_title("Per-type false-positive rate (test, benign variants)")
    fig.tight_layout(); fig.savefig(out, dpi=120); plt.close(fig)


def _split(scored, s):
    return [x for x in scored if x.split == s]


def evaluate_seed(seed: float):
    """Rebuild the labeled split with `seed` and evaluate; return everything the report needs."""
    from evaluation import build_dataset
    build_dataset.build(int(seed), 0.3)
    rows = list(csv.DictReader((LABELED_DIR / "labels.csv").open(encoding="utf-8")))

    new = analyse_all(rows, multi_offset=True, encoded=True)
    old = analyse_all(rows, multi_offset=False, encoded=False)
    t_new = tune_threshold(_split(new, "tuning"))
    t_old = tune_threshold(_split(old, "tuning"))
    t_ent = tune_threshold(_split(new, "tuning"), key=lambda s: s.entropy)
    test_new, test_old = _split(new, "test"), _split(old, "test")
    return {
        "seed": int(seed), "n": len(rows),
        "n_tuning": len(_split(new, "tuning")), "n_test": len(test_new),
        "t_new": t_new, "t_old": t_old, "t_ent": t_ent,
        "test_new": test_new, "test_old": test_old,
        "cm_new": confusion(test_new, t_new),
        "cm_old": confusion(test_old, t_old),
        "cm_ent": confusion(test_new, t_ent, key=lambda s: s.entropy),
        "roc_comb": roc_auc(test_new),
        "roc_ent": roc_auc(test_new, key=lambda s: s.entropy),
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="File-level evaluation on the labeled dataset.")
    ap.add_argument("--seed", type=int, default=2025, help="FRESH split seed (unbiased result)")
    ap.add_argument("--compare-seed", type=int, default=1234, help="original split seed (comparison)")
    args = ap.parse_args(argv)

    # Evaluate the ORIGINAL seed first, then the FRESH seed last so the dataset on disk ends
    # on the fresh split (the one we report as the headline).
    old_res = evaluate_seed(args.compare_seed)
    fresh = evaluate_seed(args.seed)

    def headline(res):
        return metrics(*res["cm_new"])

    lines: list[str] = ["# File-level evaluation on the NapierOne labeled dataset\n"]
    lines.append(
        "> **Avoiding test-set leakage.** The structural-validity gate (and the earlier "
        "magic-byte gate) were designed *after* inspecting the first split "
        f"(seed {args.compare_seed}). To report an unbiased number, the detector is frozen "
        f"and the split is rebuilt with a FRESH seed ({args.seed}), assigned by source file. "
        "The fresh-seed result below is the headline; the original seed is shown only for "
        "comparison.\n")

    lines.append(f"## FRESH split (seed {fresh['seed']}) - unbiased headline\n")
    lines.append(f"Samples: {fresh['n']} (split by source file: tuning {fresh['n_tuning']} / "
                 f"test {fresh['n_test']}). Thresholds tuned on tuning only "
                 f"(combined={fresh['t_new']}, old={fresh['t_old']}, entropy-only={fresh['t_ent']:.2f}).\n")
    lines += _md_metrics("NEW detector (structural gate + multi-offset + encoded)", headline(fresh), fresh["cm_new"])
    lines += _md_metrics("OLD detector (first-window entropy, magic only)", metrics(*fresh["cm_old"]), fresh["cm_old"])
    lines += _md_metrics("Entropy-only", metrics(*fresh["cm_ent"]), fresh["cm_ent"])
    lines.append(f"\nAUC (test): combined={fresh['roc_comb'][2]:.3f} vs entropy-only={fresh['roc_ent'][2]:.3f}\n")

    lines.append("## Per file type - FRESH split (test)\n")
    lines += _per_group(fresh["test_new"], fresh["t_new"], "source_type")
    lines.append("\n## Per variant - FRESH split (test), incl. enc_header_kept\n")
    lines += _per_group(fresh["test_new"], fresh["t_new"], "variant")
    lines.append(
        "\n*enc_header_kept is the hardest variant: it preserves the real magic bytes, so it "
        "is caught only for types with a structural check (zip/docx/xlsx/pptx, png, gzip, "
        "pdf, jpg). Media types (mp3/mp4/mkv) have no cheap structural check, so a header-kept "
        "media file is trusted on its magic and evades - a known limitation that a real EDR "
        "would close with format-aware parsers or kernel file->PID attribution.*")

    om = headline(old_res)
    lines.append(f"\n## Original split (seed {old_res['seed']}) - for comparison only\n")
    lines += _md_metrics("NEW detector", om, old_res["cm_new"])
    lines.append(f"\nAUC (test): combined={old_res['roc_comb'][2]:.3f} vs "
                 f"entropy-only={old_res['roc_ent'][2]:.3f}\n")

    config.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (config.RESULTS_DIR / "dataset_results.md").write_text("\n".join(lines), encoding="utf-8")
    chart_confusion(fresh["cm_new"], config.RESULTS_DIR / "dataset_confusion.png")
    chart_roc({"combined": fresh["roc_comb"], "entropy-only": fresh["roc_ent"]},
              config.RESULTS_DIR / "dataset_roc.png")
    chart_per_type_fpr(fresh["test_new"], fresh["t_new"], config.RESULTS_DIR / "dataset_per_type_fpr.png")

    print("\n".join(lines))
    print(f"\nsaved -> {config.RESULTS_DIR / 'dataset_results.md'} + 3 charts (dataset left on fresh seed {fresh['seed']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
