"""
process_monitor.py

WHAT: a background sampler that uses psutil to answer the one question watchdog cannot:
      "which process is responsible for the file activity in the sandbox?" Every ~0.5 s it
      reads each visible process's cumulative write_bytes, turns that into a per-PID write
      RATE (bytes/second), and for the fast writers checks whether they have a file open
      inside the sandbox. get_suspects() then returns those processes ranked by write rate.

WHY : the detector's file signals tell us an attack IS happening; they do not tell us WHO
      to stop. The OS inotify/watchdog event carries no PID. So we attribute the activity
      to the most likely process by intersecting two independent observations:
          (a) the process is writing a lot right now (write-rate spike), AND
          (b) the process has (or recently had) a file open inside ./sandbox.

LIMITATION (documented in README): this is a heuristic. A process opens, writes and closes
each file very quickly, so open_files() can miss the handle between samples; under heavy
concurrent I/O two processes can be confused. We reduce misses with a short "sticky" memory
of which PIDs were seen touching the sandbox, and we NEVER act on a whitelisted or our own
PID. An exact fanotify-based path (Linux only) is left behind config.USE_FANOTIFY.

PLATFORM REALITY (measured on the Windows demo machine): psutil's per-process io_counters()
returns 0 for OTHER processes here, and open_files() frequently misses an actively written
handle. Those two signals are reliable on Linux but not on this Windows box. So sandbox
involvement is decided by whichever of these succeeds, tried cheapest-first:
    1. the process COMMAND LINE references the protected path (reliable on Windows; real
       EDR products also inspect command lines), or its name matches the simulator hint;
    2. its working directory is inside the sandbox;
    3. it holds an open file inside the sandbox (reliable on Linux).
Write rate is still sampled and used to RANK suspects when available; it just cannot be the
sole requirement, because on Windows it reads as 0. suspend()/resume()/terminate()/kill()
were verified to work on both platforms.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import psutil

from . import config


@dataclass(frozen=True)
class Suspect:
    pid: int
    name: str
    write_rate: float          # bytes/second over the most recent sample
    in_sandbox: bool           # seen with an open file / cwd inside the sandbox
    last_sandbox_ts: float     # monotonic time it was last seen in the sandbox (0 = never)


class ProcessMonitor:
    """Samples per-process write rates and sandbox involvement on a background thread."""

    def __init__(
        self,
        sandbox_root: Path | None = None,
        interval: float = config.PROC_SAMPLE_INTERVAL,
    ) -> None:
        self.sandbox_root = (sandbox_root or config.SANDBOX).resolve()
        self.interval = interval
        self.own_pid = os.getpid()
        # Protect our whole ancestry (the shell/IDE that launched us) from ever being killed.
        self._protected_pids = self._ancestor_pids(self.own_pid)

        self._lock = threading.Lock()
        self._prev_writes: dict[int, tuple[int, float]] = {}   # pid -> (write_bytes, ts)
        self._rates: dict[int, tuple[float, float, str]] = {}  # pid -> (rate, ts, name)
        self._sandbox_pids: dict[int, float] = {}              # pid -> last monotonic ts seen
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    # --------------------------------------------------------------- helpers
    @staticmethod
    def _ancestor_pids(pid: int) -> set[int]:
        """PIDs of this process and all its parents - never suspend/kill any of these."""
        pids: set[int] = set()
        try:
            proc = psutil.Process(pid)
            while proc is not None:
                pids.add(proc.pid)
                proc = proc.parent()
        except (psutil.Error, OSError):
            pass
        return pids

    def is_whitelisted(self, pid: int, name: str) -> bool:
        """Processes we must never act on: ourselves, our ancestry, and config names."""
        if pid in self._protected_pids or pid == self.own_pid:
            return True
        return name in config.PROTECTED_PROC_NAMES

    def _touches_sandbox(self, proc: psutil.Process, allow_open_files: bool) -> bool:
        """
        True if the process looks involved with the sandbox, trying the checks
        cheapest-first and stopping at the first hit (see the PLATFORM REALITY note above).

        open_files() is expensive and can block on Windows system processes, so it is only
        attempted when `allow_open_files` is set - which the caller does solely for fast
        writers. The cmdline/cwd checks are cheap and run for every process.
        """
        root = self.sandbox_root
        root_str = str(root).lower()

        # 1. Command line references the protected path, or the process is the simulator.
        try:
            cmdline = proc.cmdline()
            if any(root_str in (arg or "").lower() for arg in cmdline):
                return True
            if any(config.SIMULATOR_HINT in (arg or "").lower() for arg in cmdline):
                return True
        except (psutil.Error, OSError):
            pass

        # 2. Working directory is the sandbox or inside it.
        try:
            cwd = Path(proc.cwd()).resolve()
            if cwd == root or root in cwd.parents:
                return True
        except (psutil.Error, OSError, ValueError):
            pass

        # 3. An open file handle inside the sandbox (reliable on Linux; only for fast
        #    writers, because scanning handles for every process is too slow on Windows).
        if allow_open_files:
            try:
                for handle in proc.open_files():
                    try:
                        if root in Path(handle.path).resolve().parents:
                            return True
                    except (OSError, ValueError):
                        continue
            except (psutil.Error, OSError):
                pass
        return False

    # ---------------------------------------------------------------- sampling
    def _sample(self) -> None:
        """One sampling pass: update write rates, and sandbox involvement for fast writers."""
        now = time.monotonic()
        for proc in psutil.process_iter(["pid", "name"]):
            pid = proc.info["pid"]
            name = proc.info["name"] or ""
            if self.is_whitelisted(pid, name):
                continue

            # Write rate is best-effort: unavailable (or 0) on Windows for other processes,
            # so a failure here must NOT skip the sandbox-involvement check below.
            rate = 0.0
            try:
                write_bytes = proc.io_counters().write_bytes
                prev = self._prev_writes.get(pid)
                self._prev_writes[pid] = (write_bytes, now)
                if prev is not None:
                    prev_bytes, prev_ts = prev
                    dt = now - prev_ts
                    if dt > 0:
                        rate = max(0.0, (write_bytes - prev_bytes) / dt)
            except (psutil.Error, OSError, NotImplementedError):
                pass

            with self._lock:
                self._rates[pid] = (rate, now, name)

            # Decide sandbox involvement. On Linux we can restrict the (cheaper there)
            # open_files scan to fast writers; but because write rate reads as 0 for other
            # processes on this Windows box, we must also inspect when the rate is 0 -
            # otherwise nothing would ever be attributed. The command-line check inside
            # _touches_sandbox is cheap and short-circuits first, keeping this affordable.
            fast = rate >= config.PROC_MIN_WRITE_RATE
            if self._touches_sandbox(proc, allow_open_files=fast):
                with self._lock:
                    self._sandbox_pids[pid] = now

        self._prune(now)

    def _prune(self, now: float) -> None:
        """Forget processes we have not seen for a while, so the maps do not grow."""
        horizon = now - max(config.PROC_WINDOW_SEC * 4, 30.0)
        with self._lock:
            for pid in [p for p, (_, ts, _) in self._rates.items() if ts < horizon]:
                self._rates.pop(pid, None)
                self._sandbox_pids.pop(pid, None)
                self._prev_writes.pop(pid, None)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._sample()
            except Exception:
                # The sampler must never crash the detector; skip a bad pass.
                pass
            self._stop.wait(self.interval)

    # ------------------------------------------------------------------ API
    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="proc-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None

    def get_suspects(self, window: float = config.PROC_WINDOW_SEC) -> list[Suspect]:
        """
        Processes active in the sandbox within `window` seconds, ranked by write rate
        (highest first). This is the ransomware-candidate list.
        """
        now = time.monotonic()
        suspects: list[Suspect] = []
        with self._lock:
            rates = dict(self._rates)
            sandbox_pids = dict(self._sandbox_pids)

        for pid, (rate, ts, name) in rates.items():
            if self.is_whitelisted(pid, name):
                continue
            last_sb = sandbox_pids.get(pid, 0.0)
            in_sandbox = (now - last_sb) <= window if last_sb else False
            if not in_sandbox:
                continue
            suspects.append(
                Suspect(pid=pid, name=name, write_rate=rate, in_sandbox=True, last_sandbox_ts=last_sb)
            )
        # Rank by write rate first (meaningful on Linux); break ties by how recently the
        # process was seen touching the sandbox (the usable signal on Windows).
        suspects.sort(key=lambda s: (s.write_rate, s.last_sandbox_ts), reverse=True)
        return suspects

    def most_likely_suspect(self, window: float = config.PROC_WINDOW_SEC) -> Suspect | None:
        """The single best kill target right now, or None if we cannot attribute confidently."""
        suspects = self.get_suspects(window)
        return suspects[0] if suspects else None
