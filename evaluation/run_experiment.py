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


def _fresh_corpus(scale: int = 1) -> None:
    _sweep_stray_simulators()
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


def run_attack_trial(order: str, delay: float, scale: int = 1) -> TrialResult:
    _fresh_corpus(scale)
    monitor = _start_monitor()
    files_total = len(monitor.baseline)

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
    args = parser.parse_args(argv)

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
    out = config.RESULTS_DIR / "results.json"
    import json

    out.write_text(json.dumps([asdict(r) for r in results], indent=2), encoding="utf-8")
    print(f"\nwrote {len(results)} trial results to {out}")
    print("render the report with:  python -m evaluation.report")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
