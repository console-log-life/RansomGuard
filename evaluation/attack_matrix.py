"""
attack_matrix.py

WHAT: runs every attack mode against the detector, WITH and WITHOUT canaries (the ablation),
      and records for each cell: was it detected, how fast, how many files encrypted, how
      many recovered, whether the folder ended clean (ground truth), whether the RIGHT
      process was killed, whether it was already clean before the final stop() sweep, and -
      the headline comparison - whether the ORIGINAL ("old") detector would have caught it.

WHY : this is the "why advanced" evidence. The smart modes (intermittent, base64) are built
      to slip past entropy/magic/canary. By scoring each attack with the old signal set and
      the new one, the table shows exactly which attacks the upgrades newly catch.

Two measurements per cell:
  * EFFICACY (detected? / would-old-catch?): an offline, deterministic replay of the
    detector's signals over the post-attack folder - once with the new features off ("old")
    and once on ("new"). No live timing, so these columns are reproducible.
  * OPERATIONAL (time / encrypted / recovered / clean / correct-kill): a live enforcing run,
    which actually suspends, recovers and kills.

Run:  python -m evaluation.attack_matrix            # full matrix
      python -m evaluation.attack_matrix --quick    # 2 modes, canaries on only
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ransomguard import baseline as baseline_mod
from ransomguard import canary as canary_mod
from ransomguard import config, entropy
from ransomguard.logger import EventLogger, read_events
from ransomguard.monitor import RansomGuardMonitor
from ransomguard.scorer import Scorer, evaluate_signals
from evaluation.run_experiment import (
    PYTHON, ROOT, _kill_tree, _snapshot_hashes, _start_monitor, _first, _sweep_stray_simulators,
)


CORPUS = "synthetic"


def _text_corpus() -> None:
    """The matrix corpus.

    synthetic: a text-only corpus (no magic bytes) - the hard case that isolates the
    entropy/encoded signals, so the before/after comparison is not masked by broken headers.
    napierone: real files of mixed types, where the magic-byte and structural signals also
    get to contribute (so the old detector looks stronger - which is the honest picture).
    """
    _sweep_stray_simulators()
    if CORPUS == "napierone":
        from evaluation import run_experiment as rx
        rx._napierone_corpus(n_files=60)
        return
    subprocess.run(
        [PYTHON, "tools/make_test_files.py", "--clean", "--text-only"],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
    )


MODES = ["full", "slow", "no-rename", "base64", "intermittent"]
# Per-file delay for the LIVE operational run. A 6-file text attack at ~0.1 s finishes in
# under a second - before a PID can be attributed - so almost every cell showed no_kill.
# These slower rates give the attribution/kill path time to fire (slow stays slowest). The
# efficacy columns (detected? / would-old-catch?) come from the delay-0 offline replay and
# are unaffected by this.
MODE_DELAY = {"full": 0.5, "slow": 1.5, "no-rename": 0.5, "base64": 0.5, "intermittent": 0.5}


@dataclass
class MatrixRow:
    mode: str
    canaries: bool
    detected_new: bool = False
    would_old_catch: bool = False
    detection_time_s: float | None = None
    files_encrypted: int = 0
    files_recovered: int = 0
    folder_clean: bool = False
    clean_before_sweep: bool = False
    correct_kill: str = "n/a"   # yes | wrong_pid | no_kill


# ----------------------------------------------------- offline signal replay
def _replay_detects(root: Path, base: dict, canaries: dict, new_features: bool) -> bool:
    """Replay the detector's signals over the current folder; True if it would alert.

    `new_features` toggles the B2 upgrades (multi-offset entropy + encoded detection) so we
    can score the same attack with the OLD and the NEW detector.
    """
    saved = (config.FEATURE_MULTI_OFFSET_ENTROPY, config.FEATURE_ENCODED_DETECTION)
    config.FEATURE_MULTI_OFFSET_ENTROPY, config.FEATURE_ENCODED_DETECTION = new_features, new_features
    try:
        scorer = Scorer()
        actor = "replay"
        alerted = False
        base_keys = set(base)

        # Events for the files that existed before the attack: deleted or modified.
        for key, entry in base.items():
            p = Path(key)
            touched = canary_mod.canary_touched(p, canaries) if canaries else False
            if not p.exists():
                reasons = evaluate_signals(None, entry, canary_touched=touched, deleted=True)
            else:
                if baseline_mod.sha256_file(p) == entry.sha256:
                    continue  # unchanged
                try:
                    cur = entropy.analyse_file(p)
                except OSError:
                    continue
                reasons = evaluate_signals(cur, entry, canary_touched=touched)
            scorer.observe(actor, reasons)
            if scorer.should_act(actor):
                alerted = True

        # New files that appeared (e.g. .locked copies).
        backup = config.BACKUP_DIR.resolve()
        for p in root.rglob("*"):
            if p.is_dir() or backup in p.resolve().parents:
                continue
            if str(p.resolve()) in base_keys:
                continue
            touched = canary_mod.canary_touched(p, canaries) if canaries else False
            try:
                cur = entropy.analyse_file(p)
            except OSError:
                continue
            scorer.observe(actor, evaluate_signals(cur, None, canary_touched=touched))
            if scorer.should_act(actor):
                alerted = True
        return alerted
    finally:
        config.FEATURE_MULTI_OFFSET_ENTROPY, config.FEATURE_ENCODED_DETECTION = saved


def _efficacy(mode: str, canaries_on: bool) -> tuple[bool, bool]:
    """Generate the attack with NO monitor, then replay old vs new detectors. (detected_new,
    would_old_catch)."""
    config.ENABLE_CANARIES = canaries_on
    _text_corpus()
    base = baseline_mod.build_baseline(config.PROTECTED_DIR)
    canaries = canary_mod.deploy_canaries(config.PROTECTED_DIR) if canaries_on else {}

    sim = subprocess.Popen(
        [PYTHON, "-m", "simulator.fake_ransomware", "--mode", mode, "--delay", "0", "--order", "asis"],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        sim.wait(timeout=40)
    except subprocess.TimeoutExpired:
        pass
    _kill_tree(sim)

    new_catch = _replay_detects(config.PROTECTED_DIR, base, canaries, new_features=True)
    old_catch = _replay_detects(config.PROTECTED_DIR, base, canaries, new_features=False)
    subprocess.run([PYTHON, "-m", "simulator.undo"], cwd=ROOT,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return new_catch, old_catch


# ----------------------------------------------------------- live operational run
def _operational(mode: str, canaries_on: bool) -> dict:
    config.ENABLE_CANARIES = canaries_on
    _text_corpus()
    monitor = _start_monitor()
    clean = _snapshot_hashes()

    if config.SIM_PID_FILE.exists():
        config.SIM_PID_FILE.unlink()
    sim_start = time.time()
    sim = subprocess.Popen(
        [PYTHON, "-m", "simulator.fake_ransomware", "--mode", mode,
         "--delay", str(MODE_DELAY[mode]), "--order", "alphabetical"],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    # Read the simulator's real worker PID from the file it writes at startup.
    sim_pid = None
    for _ in range(40):
        try:
            sim_pid = int(config.SIM_PID_FILE.read_text())
            break
        except (OSError, ValueError):
            time.sleep(0.05)
    try:
        sim.wait(timeout=40)
    except subprocess.TimeoutExpired:
        pass
    time.sleep(2.0)                       # let in-attack responses finish
    pre_sweep = _snapshot_hashes()        # folder state BEFORE the final stop() sweep
    monitor.stop()                        # this triggers the final recovery sweep
    final = _snapshot_hashes()
    _kill_tree(sim)

    events = read_events(config.LOG_FILE)
    suspend_at = _first(events, "suspend", "detected_at")
    killed_pid = _first(events, "kill", "pid")
    recoveries = [e for e in events if e["event"] == "recovery"]
    correct = "no_kill"
    if killed_pid is not None:
        correct = "yes" if (sim_pid is not None and int(killed_pid) == sim_pid) else "wrong_pid_suspended"

    dt = round(float(suspend_at) - sim_start, 3) if suspend_at is not None else None
    return {
        "detection_time_s": dt if (dt is None or dt >= 0) else None,
        # Total files the attacker encrypted before being stopped, and how many recovery
        # restored, summed across all response waves (what the log actually did).
        "files_encrypted": sum(int(r.get("affected", 0)) for r in recoveries),
        "files_recovered": sum(int(r.get("restored", 0)) for r in recoveries),
        "folder_clean": final == clean,               # ground truth
        "clean_before_sweep": pre_sweep == clean,      # clean already, before stop()'s sweep?
        "correct_kill": correct,
    }


def run_cell(mode: str, canaries_on: bool) -> MatrixRow:
    detected_new, would_old = _efficacy(mode, canaries_on)
    op = _operational(mode, canaries_on)
    return MatrixRow(
        mode=mode, canaries=canaries_on, detected_new=detected_new, would_old_catch=would_old,
        detection_time_s=op["detection_time_s"], files_encrypted=op["files_encrypted"],
        files_recovered=op["files_recovered"], folder_clean=op["folder_clean"],
        clean_before_sweep=op["clean_before_sweep"], correct_kill=op["correct_kill"],
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Attack-mode x canary-ablation matrix.")
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--corpus", choices=("synthetic", "napierone"), default="synthetic",
                        help="text-only synthetic corpus, or real NapierOne files")
    args = parser.parse_args(argv)

    global CORPUS
    CORPUS = args.corpus
    print(f"corpus: {CORPUS}")

    modes = ["full", "base64"] if args.quick else MODES
    canary_states = [True] if args.quick else [True, False]

    rows: list[MatrixRow] = []
    total = len(modes) * len(canary_states)
    i = 0
    for canaries_on in canary_states:
        for mode in modes:
            i += 1
            print(f"[{i}/{total}] mode={mode} canaries={'on' if canaries_on else 'off'} ...")
            rows.append(run_cell(mode, canaries_on))

    config.ENABLE_CANARIES = True  # restore default
    config.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    suffix = "" if CORPUS == "synthetic" else f"_{CORPUS}"
    out = config.RESULTS_DIR / f"attack_matrix{suffix}.json"
    out.write_text(json.dumps([asdict(r) for r in rows], indent=2), encoding="utf-8")
    print(f"\nwrote {len(rows)} matrix rows to {out}")
    print("render with:  python -m evaluation.report")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
