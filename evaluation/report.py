"""
report.py

WHAT: turns evaluation/results/results.json into (1) a Markdown results table printed to the
      console and saved to results.md, and (2) two or three charts saved as PNGs.

WHY : this is what goes into the project report and the viva slides. The table gives the
      exact per-trial numbers; the charts show the two headline stories at a glance -
      "detection is fast and files encrypted stay low" and "recovery restores ~100% while
      false positives stay at 0".

Run:  python -m evaluation.report
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from statistics import mean

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import matplotlib

matplotlib.use("Agg")  # headless: just write PNG files, never open a window
import matplotlib.pyplot as plt  # noqa: E402

from ransomguard import config  # noqa: E402


def load_results() -> list[dict]:
    path = config.RESULTS_DIR / "results.json"
    if not path.exists():
        raise SystemExit("no results.json - run `python -m evaluation.run_experiment` first")
    return json.loads(path.read_text(encoding="utf-8"))


def load_matrix() -> list[dict]:
    path = config.RESULTS_DIR / "attack_matrix.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []


def build_matrix_table(rows: list[dict]) -> str:
    """Render the attack-mode x canary-ablation matrix, incl. the before/after column."""
    lines = ["## Attack matrix (smart attacks vs. the detector)\n"]
    lines.append("| mode | canaries | detected (new)? | would OLD detector catch? | "
                 "detection (s) | encrypted | recovered | folder clean | clean pre-sweep | correct kill |")
    lines.append("|------|----------|-----------------|---------------------------|"
                 "---------------|-----------|-----------|--------------|-----------------|--------------|")
    for r in rows:
        det = "yes" if r["detected_new"] else "**NO**"
        old = "yes" if r["would_old_catch"] else "**NO (new catch)**"
        lines.append(
            f"| {r['mode']} | {'on' if r['canaries'] else 'off'} | {det} | {old} | "
            f"{_fmt(r['detection_time_s'])} | {r['files_encrypted']} | {r['files_recovered']} | "
            f"{'yes' if r['folder_clean'] else 'NO'} | {'yes' if r['clean_before_sweep'] else 'no'} | "
            f"{r['correct_kill']} |"
        )
    # The headline: attacks the new detector catches that the old one would have missed.
    gained = [r for r in rows if r["detected_new"] and not r["would_old_catch"]]
    lines.append(
        f"\n**Before/after:** {len(gained)} of {len(rows)} attack cells are caught by the new "
        f"detector but would have slipped past the original entropy/magic/canary detector"
    )
    for r in gained:
        lines.append(f"- {r['mode']} (canaries {'on' if r['canaries'] else 'off'})")
    clean = sum(1 for r in rows if r["folder_clean"])
    lines.append(f"\n**Recovery:** folder fully clean in {clean}/{len(rows)} cells (ground truth).")
    return "\n".join(lines)


def chart_old_vs_new(rows: list[dict], out: Path) -> None:
    """Grouped bars: would-old-catch vs detected-new, for the canaries-off ablation."""
    cells = [r for r in rows if not r["canaries"]] or rows
    if not cells:
        return
    labels = [r["mode"] for r in cells]
    old = [1 if r["would_old_catch"] else 0 for r in cells]
    new = [1 if r["detected_new"] else 0 for r in cells]
    x = range(len(cells))
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.bar([i - 0.2 for i in x], old, width=0.4, label="old detector", color="#95a5a6")
    ax.bar([i + 0.2 for i in x], new, width=0.4, label="new detector", color="#2980b9")
    ax.set_xticks(list(x)); ax.set_xticklabels(labels)
    ax.set_yticks([0, 1]); ax.set_yticklabels(["missed", "caught"])
    ax.set_title("Detection by attack mode (canaries OFF): old vs new detector")
    ax.legend()
    fig.tight_layout(); fig.savefig(out, dpi=120); plt.close(fig)


def _fmt(value, suffix="") -> str:
    return "-" if value is None else f"{value}{suffix}"


def build_table(results: list[dict]) -> str:
    attacks = [r for r in results if r["kind"] == "attack"]
    benign = [r for r in results if r["kind"] == "benign"]
    lines: list[str] = []

    lines.append("## Attack trials\n")
    lines.append("| # | order | delay | files | detection (s) | attributed | killed | "
                 "encrypted | final recovered | folder clean |")
    lines.append("|---|-------|-------|-------|---------------|------------|--------|"
                 "-----------|-----------------|--------------|")
    for i, r in enumerate(attacks, 1):
        recovered = r.get("final_recovered", r["files_restored"])
        clean = r.get("final_clean", r["files_restored"] == r["files_encrypted"])
        lines.append(
            f"| {i} | {r['order']} | {r['delay']}s | {r['files_total']} | "
            f"{_fmt(r['detection_time_s'])} | {'yes' if r['attributed'] else 'no'} | "
            f"{'yes' if r['killed'] else 'no'} | {r['files_encrypted']} | "
            f"{recovered}/{r['files_total']} | {'yes' if clean else 'NO'} |"
        )

    det = [r["detection_time_s"] for r in attacks if r["detection_time_s"] is not None]
    enc = [r["files_encrypted"] for r in attacks]
    rate = [r["recovery_rate"] for r in attacks]
    lines.append("\n**Attack summary**\n")
    lines.append(f"- trials: {len(attacks)}")
    lines.append(
        f"- attributed: {sum(r['attributed'] for r in attacks)}/{len(attacks)}; "
        f"killed: {sum(r['killed'] for r in attacks)}/{len(attacks)} "
        f"(fast attacks can finish before a kill; recovery still restores them)"
    )
    if det:
        lines.append(f"- detection time: mean {mean(det):.2f}s, min {min(det):.2f}s, max {max(det):.2f}s")
    lines.append(f"- files encrypted before stop: mean {mean(enc):.1f}, min {min(enc)}, max {max(enc)}")
    lines.append(f"- recovery rate (recovery self-report): mean {mean(rate) * 100:.1f}%")
    clean_count = sum(1 for r in attacks if r.get("final_clean"))
    leftover = sum(r.get("leftover_locked", 0) for r in attacks)
    lines.append(f"- **folder fully clean at end (ground truth): {clean_count}/{len(attacks)} trials**")
    lines.append(f"- leftover .locked artifacts across all trials: {leftover}")
    total_failed = sum(r["files_failed"] for r in attacks)
    lines.append(f"- files that failed to restore: {total_failed}")

    lines.append("\n## Benign trials (false-positive test)\n")
    lines.append("| trial | files | false positives | wrongful kills |")
    lines.append("|-------|-------|-----------------|----------------|")
    for r in benign:
        lines.append(f"| {r['label']} | {r['files_total']} | {r['false_positives']} | {r['wrongful_kills']} |")
    lines.append(
        f"\n**Benign summary:** {sum(r['false_positives'] for r in benign)} false positives and "
        f"{sum(r['wrongful_kills'] for r in benign)} wrongful kills across {len(benign)} runs."
    )
    return "\n".join(lines)


def chart_detection_and_encrypted(attacks: list[dict], out: Path) -> None:
    """Bar chart: files encrypted before stop, per trial, annotated with detection time."""
    labels = [f"{r['order'][:4]}\n{r['delay']}s" for r in attacks]
    encrypted = [r["files_encrypted"] for r in attacks]
    restored = [r["files_restored"] for r in attacks]
    x = range(len(attacks))

    fig, ax = plt.subplots(figsize=(11, 4.5))
    ax.bar([i - 0.2 for i in x], encrypted, width=0.4, label="encrypted before stop", color="#c0392b")
    ax.bar([i + 0.2 for i in x], restored, width=0.4, label="restored (verified)", color="#27ae60")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, fontsize=8)
    ax.set_ylabel("files")
    ax.set_title("Files encrypted before the attacker was stopped vs. files restored")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out, dpi=120)
    plt.close(fig)


def chart_detection_time(attacks: list[dict], out: Path) -> None:
    """Detection time per trial (only trials where a kill happened)."""
    pts = [(f"{r['order'][:4]} {r['delay']}s", r["detection_time_s"])
           for r in attacks if r["detection_time_s"] is not None]
    if not pts:
        return
    labels, times = zip(*pts)
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.plot(range(len(times)), times, marker="o", color="#2980b9")
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=8)
    ax.set_ylabel("detection time (s)")
    ax.set_title("Time from attack start to attacker suspended")
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(out, dpi=120)
    plt.close(fig)


def chart_recovery_vs_fp(results: list[dict], out: Path) -> None:
    """Two-panel summary: recovery rate across attacks, false positives across benign runs."""
    attacks = [r for r in results if r["kind"] == "attack"]
    benign = [r for r in results if r["kind"] == "benign"]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4))
    ax1.bar(range(len(attacks)), [r["recovery_rate"] * 100 for r in attacks], color="#27ae60")
    ax1.axhline(100, color="#555", linestyle="--", linewidth=1)
    ax1.set_ylim(0, 110)
    ax1.set_ylabel("recovery rate (%)")
    ax1.set_xlabel("attack trial")
    ax1.set_title("Hash-verified recovery rate")

    ax2.bar([r["label"] for r in benign], [r["false_positives"] for r in benign], color="#e67e22")
    ax2.set_ylim(0, max(1, *[r["false_positives"] for r in benign]) + 1)
    ax2.set_ylabel("false positives")
    ax2.set_title("False alarms during benign work")
    fig.tight_layout()
    fig.savefig(out, dpi=120)
    plt.close(fig)


def main() -> int:
    results = load_results()
    table = build_table(results)
    matrix = load_matrix()
    full = table
    if matrix:
        full = table + "\n\n" + build_matrix_table(matrix)
    print("\n" + full + "\n")

    config.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (config.RESULTS_DIR / "results.md").write_text(full, encoding="utf-8")

    attacks = [r for r in results if r["kind"] == "attack"]
    chart_detection_and_encrypted(attacks, config.RESULTS_DIR / "encrypted_vs_restored.png")
    chart_detection_time(attacks, config.RESULTS_DIR / "detection_time.png")
    chart_recovery_vs_fp(results, config.RESULTS_DIR / "recovery_vs_false_positives.png")
    if matrix:
        chart_old_vs_new(matrix, config.RESULTS_DIR / "old_vs_new_detection.png")

    print(f"saved table  -> {config.RESULTS_DIR / 'results.md'}")
    print(f"saved charts -> {config.RESULTS_DIR}/*.png")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
