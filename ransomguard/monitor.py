"""
monitor.py

WHAT: the live engine. It watches ./sandbox/protected with watchdog, and on every file
      event it measures the file, asks the scorer how suspicious the activity now is, and
      logs everything to events.jsonl. In PHASE 3 it is LOG-ONLY: when the score crosses
      the threshold it records an "ALERT" but does not suspend or kill anything yet
      (that is phase 4) and does not restore files yet (phase 5).

WHY : this is where the three signals come together in real time. Keeping the decision
      logic in one small, synchronous method (`handle_event`) means we can unit-test the
      whole detection pipeline by feeding it fake events, without threads or timing - and
      the watchdog callback is then just a thin forwarder.

Attribution limitation (important, see README): watchdog/inotify tells us WHAT file
changed, never WHICH process changed it. In phase 3 we therefore score a single global
actor, "sandbox". Phase 4 adds process_monitor.py, which attributes events to a PID by
combining open-files-in-sandbox with write-rate spikes.

Run:  python -m ransomguard.monitor --path ./sandbox/protected
      python -m ransomguard.monitor --duration 30        # auto-stop after 30 s (demos)
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from . import baseline as baseline_mod
from . import canary as canary_mod
from . import config, entropy
from .logger import EventLogger
from .scorer import Reason, Scorer, evaluate_signals

# In phase 3 every event is attributed to this one actor (no PID attribution yet).
GLOBAL_ACTOR = "sandbox"


class RansomGuardMonitor:
    """Ties baseline + canaries + entropy + scorer + logger together for live events."""

    def __init__(
        self,
        root: Path | None = None,
        logger: EventLogger | None = None,
        scorer: Scorer | None = None,
        enforce: bool = False,
    ) -> None:
        self.root = config.ensure_inside(root or config.PROTECTED_DIR)
        self.logger = logger or EventLogger()
        self.scorer = scorer or Scorer()
        # enforce=False in phase 3 (log only). Phases 4/5 flip this on to kill + recover.
        self.enforce = enforce

        self.baseline: dict[str, baseline_mod.BaselineEntry] = {}
        self.canaries: dict[str, str] = {}
        self._observer: Observer | None = None

    # ------------------------------------------------------------------ setup
    def prepare(self, rebuild: bool = True) -> None:
        """Deploy canaries and take the clean baseline BEFORE watching starts."""
        if rebuild:
            self.canaries = canary_mod.deploy_canaries(self.root)
            self.baseline = baseline_mod.build_baseline(self.root)
            baseline_mod.save_baseline(self.baseline)
        else:
            self.canaries = canary_mod.load_canaries()
            self.baseline = baseline_mod.load_baseline()
        self.logger.log(
            "startup",
            path=str(self.root),
            files=len(self.baseline),
            canaries=len(self.canaries),
            enforce=self.enforce,
        )

    def _is_ignored(self, path: Path) -> bool:
        """Skip the backup folder and our own metadata files - they are not user data."""
        resolved = path.resolve()
        if config.BACKUP_DIR.resolve() in resolved.parents:
            return True
        return resolved.name in {
            config.BASELINE_FILE.name,
            config.CANARY_FILE.name,
            config.LOG_FILE.name,
            config.SIM_KEY_FILE.name,
        }

    # ------------------------------------------------------------- core logic
    def handle_event(
        self, kind: str, src: Path | str, dest: Path | str | None = None
    ) -> dict[str, object]:
        """
        Process one file event and return the log record. This is the heart of the
        detector and is deliberately pure/synchronous so tests can call it directly.

        kind is one of: created, modified, moved, deleted.
        """
        # For a move/rename, the interesting target is where the file ended up; but the
        # canary check must look at the ORIGINAL path, which carries the canary name.
        observed = Path(dest) if (kind == "moved" and dest) else Path(src)
        if self._is_ignored(observed):
            return {}

        canary_hit = canary_mod.canary_touched(src, self.canaries) or (
            dest is not None and canary_mod.canary_touched(dest, self.canaries)
        )

        current = None
        deleted = kind == "deleted"
        if not deleted and observed.exists() and observed.is_file():
            try:
                current = entropy.analyse_file(observed)
            except OSError:
                current = None

        key = str(observed.resolve())
        base = self.baseline.get(key) or self.baseline.get(str(Path(src).resolve()))

        reasons: list[Reason] = evaluate_signals(
            current, base, canary_touched=canary_hit, deleted=deleted
        )
        state = self.scorer.observe(GLOBAL_ACTOR, reasons)

        record = self.logger.log(
            "fs_event",
            kind=kind,
            path=str(observed.relative_to(self.root)) if key.startswith(str(self.root)) else str(observed),
            entropy=round(current.entropy, 3) if current else None,
            magic_ok=current.magic_ok if current else None,
            canary=canary_hit,
            reasons=[r.code for r in reasons],
            points=sum(r.points for r in reasons),
            score=round(state.score, 1),
        )

        if self.scorer.should_act(GLOBAL_ACTOR):
            self._on_alert(state.reasons, state.score)
        return record

    def _on_alert(self, reasons: list[Reason], score: float) -> None:
        """Threshold crossed. Phase 3: log only. Phases 4/5 override/extend this."""
        self.logger.log(
            "ALERT",
            actor=GLOBAL_ACTOR,
            score=round(score, 1),
            reasons=[f"{r.code}(+{r.points})" for r in reasons],
            action="log-only (enforcement arrives in phase 4)",
        )

    # --------------------------------------------------------------- watchdog
    def start(self) -> None:
        """Begin watching the folder recursively in a background observer thread."""
        handler = _WatchdogBridge(self)
        self._observer = Observer()
        self._observer.schedule(handler, str(self.root), recursive=True)
        self._observer.start()

    def stop(self) -> None:
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None
        self.logger.log("shutdown", actor=GLOBAL_ACTOR, score=round(self.scorer.score_of(GLOBAL_ACTOR), 1))


class _WatchdogBridge(FileSystemEventHandler):
    """Thin adapter: translate watchdog events into monitor.handle_event calls."""

    def __init__(self, monitor: RansomGuardMonitor) -> None:
        self._monitor = monitor

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._monitor.handle_event("created", event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._monitor.handle_event("modified", event.src_path)

    def on_moved(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._monitor.handle_event("moved", event.src_path, event.dest_path)

    def on_deleted(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._monitor.handle_event("deleted", event.src_path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="RansomGuard live monitor (phase 3: log-only).")
    parser.add_argument("--path", default=str(config.PROTECTED_DIR), help="folder to watch")
    parser.add_argument(
        "--no-rebuild",
        action="store_true",
        help="reuse the existing baseline/canaries instead of rebuilding them",
    )
    parser.add_argument(
        "--duration", type=float, default=0.0, help="auto-stop after N seconds (0 = run until Ctrl-C)"
    )
    args = parser.parse_args(argv)

    try:
        root = config.ensure_inside(Path(args.path))
    except config.SandboxViolation as exc:
        print(f"REFUSED: {exc}")
        return 2
    if not root.is_dir():
        print(f"not a folder: {root} (run tools/make_test_files.py first)")
        return 1

    monitor = RansomGuardMonitor(root=root, enforce=False)
    monitor.prepare(rebuild=not args.no_rebuild)
    monitor.start()
    print(f"[monitor] watching {root} (log-only). Ctrl-C to stop.")

    try:
        if args.duration > 0:
            time.sleep(args.duration)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print("\n[monitor] stopping ...")
    finally:
        monitor.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
