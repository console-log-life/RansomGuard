"""
run_experiment.py

WHAT: runs the whole system end-to-end many times and records the numbers our report is
      built on. Each ATTACK trial: build a fresh clean corpus, start the enforcing monitor,
      launch the simulator (with a given speed and traversal order), let the monitor
      detect -> suspend -> recover -> kill, then read the event log and measure what
      happened. Each BENIGN trial: run normal file activity under the same monitor and
      count false alarms.

WHY : the title of the project promises something "demo-able and measurable". This script
      is the measurement. It turns the live behaviour into four hard metrics per trial -
      detection time, files encrypted before the attacker was stopped, files restored
      (hash-verified) and false positives - over >=10 trials with different speeds and
      orders, so the results are statistical, not a single lucky demo.

Results are written to evaluation/results/results.json for report.py to render.

Run:  python -m evaluation.run_experiment              # full matrix (10 attack + 3 benign)
      python -m evaluation.run_experiment --quick      # a short smoke run
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

import psutil

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ransomguard import config
from ransomguard.logger import EventLogger, read_events
from ransomguard.monitor import RansomGuardMonitor

PYTHON = sys.executable
ROOT = config.PROJECT_ROOT


@dataclass
class TrialResult:
    kind: str                     # "attack" or "benign"
    label: str
    order: str = ""
    delay: float = 0.0
    files_total: int = 0
    detection_time_s: float | None = None  # sim start -> process suspended
    attributed: bool = False
    killed: bool = False
    files_encrypted: int = 0      # files the attacker damaged before being stopped
    files_restored: int = 0       # restored AND hash-verified against the manifest
    files_failed: int = 0
    recovery_rate: float = 1.0
    # Ground-truth check of the FINAL folder, independent of what recovery reported: how
    # many files match their clean hash, and whether any ransomware artifact survived.
    final_recovered: int = 0
    final_clean: bool = False
    leftover_locked: int = 0
    false_positives: int = 0      # ALERT events during benign work (should be 0)
    wrongful_kills: int = 0       # kills during benign work (must be 0)


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill a launched process and all its descendants (the venv launcher spawns a child
    worker, and a killed worker can leave the stub behind)."""
    try:
        parent = psutil.Process(proc.pid)
        for child in parent.children(recursive=True):
            try:
                child.resume(); child.kill()
            except psutil.Error:
                pass
        parent.resume(); parent.kill()
    except psutil.Error:
        pass
    try:
        proc.wait(timeout=5)
    except Exception:
        pass


def _sweep_stray_simulators() -> None:
    """Belt-and-braces: make sure no simulator from a previous trial is still alive, so it
    cannot be attributed during the next trial's warm-up and corrupt the timing. This is
    harness hygiene (the detector never identifies by name - only the test runner does)."""
    for proc in psutil.process_iter(["pid", "cmdline"]):
        try:
            cmd = " ".join(proc.info.get("cmdline") or []).lower()
        except (psutil.Error, OSError):
            continue
        if "fake_ransomware" in cmd and proc.pid != __import__("os").getpid():
            try:
                proc.kill()
            except psutil.Error:
                pass


# Which corpus the trials run against: the seeded synthetic one, or real NapierOne files.
CORPUS = "synthetic"
NAPIERONE_SAMPLE = config.PROJECT_ROOT / "datasets" / "napierone_sample"
NAPIERONE_FILES = 200


def _napierone_corpus(n_files: int = NAPIERONE_FILES, seed: int = 1234) -> None:
    """Fill ./sandbox/protected with a stratified sample of REAL NapierOne files.

    Copies only - the downloaded dataset itself is never modified by the attack. Falls back
    with a clear error if the sample has not been fetched yet.
    """
    import csv as _csv
    import random as _random
    import shutil as _shutil

    manifest = NAPIERONE_SAMPLE / "manifest.csv"
    if not manifest.exists():
        raise SystemExit(f"no NapierOne sample at {manifest} - run tools/fetch_napierone.py first")

    rows = list(_csv.DictReader(manifest.open(encoding="utf-8")))
    by_type: dict[str, list[dict]] = {}
    for r in rows:
        by_type.setdefault(r["type"], []).append(r)

    # Round-robin across types so the corpus stays balanced, then trim to n_files.
    rng = _random.Random(seed)
    for lst in by_type.values():
        rng.shuffle(lst)
    picked: list[dict] = []
    i = 0
    while len(picked) < n_files and any(len(v) > i for v in by_type.values()):
        for t in sorted(by_type):
            if len(by_type[t]) > i and len(picked) < n_files:
                picked.append(by_type[t][i])
        i += 1

    root = config.ensure_inside(config.PROTECTED_DIR)
    if root.exists():
        _shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)
    for r in picked:
        dest = config.ensure_inside(root / r["path"], root)
        dest.parent.mkdir(parents=True, exist_ok=True)
        _shutil.copy2(NAPIERONE_SAMPLE / r["path"], dest)


def _fresh_corpus(scale: int = 1) -> None:
    _sweep_stray_simulators()
    if CORPUS == "napierone":
        _napierone_corpus()
        return
    subprocess.run(
        [PYTHON, "tools/make_test_files.py", "--clean", "--scale", str(scale)],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
    )


def _start_monitor() -> RansomGuardMonitor:
    if config.LOG_FILE.exists():
        config.LOG_FILE.unlink()
    monitor = RansomGuardMonitor(logger=EventLogger(echo=False), enforce=True)
    monitor.prepare(rebuild=True)
    monitor.start()
    time.sleep(1.2)  # let the process sampler warm up before the attack
    return monitor


def _first(events, name, key=None, default=None):
    for e in events:
        if e["event"] == name:
            return e if key is None else e.get(key, default)
    return default


def _snapshot_hashes() -> dict[str, str]:
    from ransomguard.baseline import sha256_file

    return {
        str(p.relative_to(config.PROTECTED_DIR)): sha256_file(p)
        for p in config.PROTECTED_DIR.rglob("*")
        if p.is_file()
    }


def run_attack_trial(order: str, delay: float, scale: int = 1) -> TrialResult:
    _fresh_corpus(scale)
    monitor = _start_monitor()
    files_total = len(monitor.baseline)
    clean = _snapshot_hashes()  # ground truth: the folder exactly as it was before the attack

    sim_start = time.time()
    proc = subprocess.Popen(
        [PYTHON, "-m", "simulator.fake_ransomware",
         "--delay", str(delay), "--order", order],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        proc.wait(timeout=40)
    except subprocess.TimeoutExpired:
        pass
    time.sleep(2.0)  # let the response thread finish suspend -> recover -> kill
    monitor.stop()
    _kill_tree(proc)  # make sure nothing from this trial lingers into the next

    events = read_events(config.LOG_FILE)
    suspend_at = _first(events, "suspend", "detected_at")
    rec = _first(events, "recovery") or {}

    result = TrialResult(
        kind="attack", label=f"{order}, delay={delay}s",
        order=order, delay=delay, files_total=files_total,
        attributed=any(e["event"] == "culprit" for e in events),
        killed=any(e["event"] == "kill" for e in events),
        files_encrypted=int(rec.get("affected", 0)),
        files_restored=int(rec.get("restored", 0)),
        files_failed=int(rec.get("failed", 0)),
    )
    if suspend_at is not None:
        dt = round(float(suspend_at) - sim_start, 3)
        # A negative time would mean the suspend predates this trial's launch, i.e. a
        # measurement artifact from a stray process; discard it rather than report it.
        result.detection_time_s = dt if dt >= 0 else None
    affected = result.files_encrypted
    result.recovery_rate = round(result.files_restored / affected, 3) if affected else 1.0

    # Ground-truth verification: compare the final folder to the clean snapshot, instead of
    # trusting what recovery reported. This catches the case where the response killed the
    # wrong process and files stayed encrypted.
    final = _snapshot_hashes()
    result.final_recovered = sum(1 for k, h in clean.items() if final.get(k) == h)
    result.leftover_locked = len(list(config.PROTECTED_DIR.rglob("*.locked")))
    result.final_clean = (final == clean) and result.leftover_locked == 0
    return result


def run_benign_trial(label: str, rounds: int = 2) -> TrialResult:
    _fresh_corpus(scale=1)
    monitor = _start_monitor()
    files_total = len(monitor.baseline)

    proc = subprocess.Popen(
        [PYTHON, "tools/benign_workload.py", "--rounds", str(rounds)],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        proc.wait(timeout=60)
    except subprocess.TimeoutExpired:
        pass
    time.sleep(1.5)
    monitor.stop()
    _kill_tree(proc)

    events = read_events(config.LOG_FILE)
    return TrialResult(
        kind="benign", label=label, files_total=files_total,
        false_positives=sum(1 for e in events if e["event"] == "ALERT"),
        wrongful_kills=sum(1 for e in events if e["event"] == "kill"),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the RansomGuard evaluation trials.")
    parser.add_argument("--quick", action="store_true", help="short smoke run (4 trials)")
    parser.add_argument("--corpus", choices=("synthetic", "napierone"), default="synthetic",
                        help="synthetic generated corpus, or real NapierOne files")
    args = parser.parse_args(argv)

    global CORPUS
    CORPUS = args.corpus
    print(f"corpus: {CORPUS}")

    if args.quick:
        attack_matrix = [("alphabetical", 0.2), ("random", 0.2)]
        benign_labels = ["benign-1"]
    else:
        # >= 10 attack trials across speeds and orders.
        delays = [0.05, 0.1, 0.2, 0.3, 0.4]
        attack_matrix = [(order, d) for order in ("alphabetical", "random") for d in delays]
        benign_labels = ["benign-1", "benign-2", "benign-3"]

    results: list[TrialResult] = []
    for i, (order, delay) in enumerate(attack_matrix, 1):
        print(f"[{i}/{len(attack_matrix)}] attack trial: {order}, delay={delay}s ...")
        results.append(run_attack_trial(order, delay))
    for label in benign_labels:
        print(f"benign trial: {label} ...")
        results.append(run_benign_trial(label))

    config.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    # Keep the two corpora in separate files so the report can show them side by side.
    suffix = "" if CORPUS == "synthetic" else f"_{CORPUS}"
    out = config.RESULTS_DIR / f"results{suffix}.json"
    import json

    out.write_text(json.dumps([asdict(r) for r in results], indent=2), encoding="utf-8")
    print(f"\nwrote {len(results)} trial results to {out}")
    print("render the report with:  python -m evaluation.report")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
