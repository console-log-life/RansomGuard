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
import threading
import time
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from . import backup as backup_mod
from . import baseline as baseline_mod
from . import canary as canary_mod
from . import config, entropy, recovery
from .logger import EventLogger
from .process_monitor import ProcessMonitor
from .responder import Responder
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
        # enforce=False in phase 3 (log only). Phase 4 flips this on to suspend + kill;
        # phase 5 adds recovery between the suspend and the kill.
        self.enforce = enforce

        # Process attribution + response are only wired up when enforcing, so the
        # log-only mode stays dependency-free and side-effect-free.
        self.proc_monitor: ProcessMonitor | None = ProcessMonitor(config.SANDBOX) if enforce else None
        self.responder: Responder | None = (
            Responder(self.logger, self.proc_monitor) if enforce else None
        )
        self._handled = False  # we act once per attack, then keep logging
        self._alert_active = False  # pauses backup refresh during an attack

        self.baseline: dict[str, baseline_mod.BaselineEntry] = {}
        self.canaries: dict[str, str] = {}
        self._observer: Observer | None = None
        self._refresh_thread: threading.Thread | None = None
        self._stop_refresh = threading.Event()
        self._enforce_thread: threading.Thread | None = None

    # ------------------------------------------------------------------ setup
    def prepare(self, rebuild: bool = True) -> None:
        """Deploy canaries and take the clean baseline BEFORE watching starts."""
        if rebuild:
            self.canaries = canary_mod.deploy_canaries(self.root)
            self.baseline = baseline_mod.build_baseline(self.root)
            baseline_mod.save_baseline(self.baseline)
            # Snapshot a clean, hash-verified backup now, while the folder is trusted.
            manifest = backup_mod.build_backup(self.root)
        else:
            self.canaries = canary_mod.load_canaries()
            self.baseline = baseline_mod.load_baseline()
            manifest = backup_mod.load_manifest()
        if self.proc_monitor is not None:
            self.proc_monitor.start()  # begin sampling write rates before any attack
        if self.enforce:
            self._start_backup_refresh()
        self.logger.log(
            "startup",
            path=str(self.root),
            files=len(self.baseline),
            canaries=len(self.canaries),
            backed_up=len(manifest),
            enforce=self.enforce,
        )

    def _start_backup_refresh(self) -> None:
        """Periodically fold benign edits into the backup, but never during an alert."""

        def loop() -> None:
            while not self._stop_refresh.wait(config.BACKUP_REFRESH_SEC):
                try:
                    n = backup_mod.refresh_clean(self.root, active_alert=self._alert_active)
                    if n:
                        self.logger.log("backup_refresh", files=n)
                except Exception:
                    pass  # a refresh failure must never take down the monitor

        self._refresh_thread = threading.Thread(target=loop, name="backup-refresh", daemon=True)
        self._refresh_thread.start()

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

        # Tell the process monitor the sandbox just changed AND by how many bytes, so it can
        # match that volume to whichever process actually wrote it (behaviour-based
        # attribution - no reliance on the process name or command line).
        if self.proc_monitor is not None:
            self.proc_monitor.note_sandbox_activity(current.size if current else 0)

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
        """
        Threshold crossed. In log-only mode (phase 3) we just record it. When enforcing
        (phase 4) we attribute the activity to a process and stop it. Phase 5 inserts
        recovery between the suspend and the kill.
        """
        self.logger.log(
            "ALERT",
            actor=GLOBAL_ACTOR,
            score=round(score, 1),
            reasons=[f"{r.code}(+{r.points})" for r in reasons],
            action="enforce" if self.enforce else "log-only",
        )
        if not self.enforce or self._handled:
            return
        self._handled = True
        self._alert_active = True  # freeze backup refresh for the duration of the response
        # Run enforcement on its own thread so the watchdog callback returns immediately.
        # This is essential: if we blocked here, no further sandbox events would be observed
        # while we poll for the culprit, and the write-volume attribution would never see
        # enough sandbox activity to match a process. Letting events keep flowing lets the
        # volume accumulate so the real attacker is identified.
        self._enforce_thread = threading.Thread(target=self._enforce, name="enforce", daemon=True)
        self._enforce_thread.start()

    def _resolve_culprit(self, timeout: float = config.ATTRIB_TIMEOUT_SEC, poll: float = 0.2):
        """
        Ask the process monitor who to stop, retrying briefly.

        The first canary hit can trip the alert before the sampler has a full write-rate
        sample, so most_likely_suspect() may be None for a moment. Because the simulator
        keeps writing, a short poll reliably surfaces it as the top sandbox writer. This
        retry is the practical answer to the PID-attribution race described in the README.
        """
        assert self.proc_monitor is not None
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            suspect = self.proc_monitor.most_likely_suspect()
            if suspect is not None:
                return suspect
            time.sleep(poll)
        return None

    def _enforce(self) -> None:
        """
        Stop the attacker and recover the files, in the safe order:
            suspend (freeze damage) -> recover from backup while frozen -> kill.

        Recovering before the kill means the process cannot encrypt any more files while we
        are restoring them, which removes a race where a resumed process re-damages a file
        we just put back.
        """
        assert self.responder is not None
        suspect = self._resolve_culprit()
        if suspect is None:
            self.logger.log(
                "enforce_unattributed",
                note="score crossed threshold but no process could be attributed",
            )
            self._recover()  # still try to repair the damage even if we cannot attribute
            return

        self.logger.log(
            "culprit", pid=suspect.pid, name=suspect.name, write_rate=int(suspect.write_rate),
        )
        # 1. Suspend only - freeze the process without killing it yet.
        resp = self.responder.respond(suspect.pid, kill_now=False)
        self.logger.log("suspend_done", pid=resp.pid, suspended=resp.suspended, refused=resp.refused)

        # 2. Recover the files while the attacker is frozen.
        self._recover()

        # 3. Now kill the frozen process.
        resp = self.responder.kill(resp)
        self.logger.log(
            "response_done", pid=resp.pid, name=resp.name,
            suspended=resp.suspended, killed=resp.killed, refused=resp.refused,
        )

    def _recover(self) -> recovery.RecoveryResult:
        """Restore the folder from the hash-verified backup and log the outcome."""
        result = recovery.recover(self.root)
        self.logger.log(
            "recovery",
            affected=result.affected,
            restored=result.restored,
            failed=result.failed,
            removed_artifacts=result.removed,
        )
        return result

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
        # Let an in-flight response finish (suspend -> recover -> kill) before we tear down.
        if self._enforce_thread is not None:
            self._enforce_thread.join(timeout=15)
            self._enforce_thread = None
        if self.proc_monitor is not None:
            self.proc_monitor.stop()
        self._stop_refresh.set()
        if self._refresh_thread is not None:
            self._refresh_thread.join(timeout=3)
            self._refresh_thread = None
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
    parser = argparse.ArgumentParser(description="RansomGuard live monitor.")
    parser.add_argument("--path", default=str(config.PROTECTED_DIR), help="folder to watch")
    parser.add_argument(
        "--enforce",
        action="store_true",
        help="suspend and kill the attributed process on alert (default: log only)",
    )
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

    monitor = RansomGuardMonitor(root=root, enforce=args.enforce)
    monitor.prepare(rebuild=not args.no_rebuild)
    monitor.start()
    mode = "ENFORCING (will suspend+kill)" if args.enforce else "log-only"
    print(f"[monitor] watching {root} ({mode}). Ctrl-C to stop.")

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
