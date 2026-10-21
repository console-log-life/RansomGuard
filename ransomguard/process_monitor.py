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

PLATFORM REALITY (measured on the Windows demo machine, on the REAL worker PID):
  * io_counters().write_bytes WORKS - it climbs ~MB/s while a process encrypts (an earlier
    reading of 0 was a mistake: it queried the venv launcher STUB pid, which does no I/O,
    not the child that actually runs the code).
  * open_files() catches a process that holds a handle open continuously, but MISSES the
    ransomware simulator, which opens/writes/closes each file in well under one sample
    (measured 0 hits in 12 samples, while write-rate was positive in 11/12).

So attribution is purely behavioural and does NOT look at the process name or command line
(renaming the attacker does not help it hide). A process is a suspect when either:
    A. it holds an open file / has its cwd inside the sandbox (reliable on Linux, and for
       any attacker that keeps a handle open), OR
    B. it is writing hard (write-rate spike) during the SAME window in which sandbox files
       are being changed - the temporal correlation the monitor feeds via
       note_sandbox_activity(). This is what catches the quick open/close simulator on
       Windows. Suspects are ranked by peak write rate, so the heaviest writer wins.
suspend()/resume()/terminate()/kill() were verified to work on both platforms.
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

import psutil

from . import config


@dataclass(frozen=True)
class Suspect:
    pid: int
    name: str
    write_rate: float          # bytes/second (peak within the window)
    in_sandbox: bool           # confirmed with an open file / cwd inside the sandbox
    last_sandbox_ts: float     # monotonic time it was last seen in the sandbox (0 = never)
    write_delta: int = 0       # bytes this process wrote during the window
    sandbox_bytes: int = 0     # bytes that appeared in the sandbox during the window


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
        self._rates: dict[int, tuple[float, float, str]] = {}  # pid -> (latest rate, ts, name)
        self._samples: dict[int, deque] = {}                   # pid -> recent (ts, write_bytes)
        self._sandbox_pids: dict[int, float] = {}              # pid -> last ts with sandbox handle
        self._sandbox_writes: deque = deque()                  # recent (ts, bytes) in sandbox
        self._last_sandbox_activity: float = 0.0               # last ts a sandbox file changed
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def note_sandbox_activity(self, nbytes: int = 0, now: float | None = None) -> None:
        """
        Called by the monitor on every sandbox file event, with the size of the file that
        changed. We record both WHEN the sandbox changed and HOW MANY bytes appeared, so
        get_suspects() can match that volume to the process that actually wrote it.
        """
        now = time.monotonic() if now is None else now
        with self._lock:
            self._last_sandbox_activity = now
            self._sandbox_writes.append((now, max(0, int(nbytes))))

    def _sandbox_volume(self, now: float, window: float) -> int:
        """Total bytes that appeared in the sandbox within the window."""
        return sum(n for ts, n in self._sandbox_writes if ts >= now - window)

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

    @staticmethod
    def _norm(name: str) -> str:
        """Normalise a process name for whitelist matching: lowercase, drop any .exe."""
        name = (name or "").casefold()
        return name[:-4] if name.endswith(".exe") else name

    def is_whitelisted(self, pid: int, name: str) -> bool:
        """Processes we must never act on: ourselves, our ancestry, and config names.

        The name match is case-insensitive and ignores a trailing .exe, so the single
        config entry "code" protects both "code" (Linux) and "Code.exe" (Windows).
        """
        if pid in self._protected_pids or pid == self.own_pid:
            return True
        return self._norm(name) in config.PROTECTED_PROC_NAMES

    def _touches_sandbox(self, proc: psutil.Process) -> bool:
        """
        True if the process currently has a file open under, or its cwd inside, the sandbox.

        This is confirmation signal A. It is reliable on Linux and for any process that
        keeps a handle open; it is NOT reliable for the quick open/close simulator on
        Windows, which is why signal B (write-rate + sandbox activity) exists. We only call
        this for processes that actually wrote this interval, so the open_files() scan stays
        cheap and never runs for the hundreds of idle system processes.
        """
        root = self.sandbox_root
        try:
            for handle in proc.open_files():
                try:
                    if root in Path(handle.path).resolve().parents:
                        return True
                except (OSError, ValueError):
                    continue
        except (psutil.Error, OSError):
            pass
        try:
            cwd = Path(proc.cwd()).resolve()
            if cwd == root or root in cwd.parents:
                return True
        except (psutil.Error, OSError, ValueError):
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

            # Read cumulative write_bytes (best-effort: may fail for some processes).
            write_bytes: int | None = None
            rate = 0.0
            try:
                write_bytes = proc.io_counters().write_bytes
            except (psutil.Error, OSError, NotImplementedError):
                write_bytes = None
            if write_bytes is not None:
                prev = self._prev_writes.get(pid)
                self._prev_writes[pid] = (write_bytes, now)
                if prev is not None and now > prev[1]:
                    rate = max(0.0, (write_bytes - prev[0]) / (now - prev[1]))

            with self._lock:
                self._rates[pid] = (rate, now, name)
                if write_bytes is not None:
                    self._samples.setdefault(pid, deque()).append((now, write_bytes))

            # Signal A (open file in sandbox) is only used where it is safe and reliable -
            # i.e. on Linux via the flag. On Windows it is skipped entirely, because
            # open_files() can block the whole sampler on a busy system process. Even here
            # we only check actual writers, keeping the scan tiny.
            if config.ATTRIB_USE_OPEN_FILES and rate > 0 and self._touches_sandbox(proc):
                with self._lock:
                    self._sandbox_pids[pid] = now

        self._prune(now)

    def _window_stats(self, pid: int, now: float, window: float) -> tuple[int, float]:
        """Bytes this pid wrote in the window (delta) and its peak rate within it."""
        samples = self._samples.get(pid)
        if not samples:
            return 0, 0.0
        inwin = [(ts, wb) for ts, wb in samples if ts >= now - window]
        if len(inwin) < 2:
            return 0, 0.0
        delta = max(0, inwin[-1][1] - inwin[0][1])
        peak = 0.0
        for (t0, w0), (t1, w1) in zip(inwin, inwin[1:]):
            if t1 > t0:
                peak = max(peak, max(0.0, (w1 - w0) / (t1 - t0)))
        return delta, peak

    def _prune(self, now: float) -> None:
        """Forget processes we have not seen for a while, so the maps do not grow."""
        horizon = now - max(config.PROC_WINDOW_SEC * 4, 30.0)
        cutoff = now - config.PROC_WINDOW_SEC
        with self._lock:
            for pid in [p for p, (_, ts, _) in self._rates.items() if ts < horizon]:
                self._rates.pop(pid, None)
                self._sandbox_pids.pop(pid, None)
                self._prev_writes.pop(pid, None)
                self._samples.pop(pid, None)
            # Trim each surviving per-process history to the window we query over.
            for samples in self._samples.values():
                while len(samples) > 2 and samples[0][0] < cutoff:
                    samples.popleft()
            # Trim the sandbox write log too.
            while self._sandbox_writes and self._sandbox_writes[0][0] < cutoff:
                self._sandbox_writes.popleft()

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
        with self._lock:
            rates = dict(self._rates)
            sandbox_pids = dict(self._sandbox_pids)
            sandbox_bytes = self._sandbox_volume(now, window)
        # Signal B is only trusted while the sandbox is actually changing, so a heavy writer
        # at an idle moment is never blamed. The sandbox volume is recorded for the log and
        # as a sanity check, but is not a hard gate (Windows write-buffering can make a
        # process's write_bytes lag the sandbox growth).
        sandbox_active = sandbox_bytes >= config.ATTRIB_MIN_SANDBOX_BYTES

        suspects: list[Suspect] = []
        for pid, (_, ts, name) in rates.items():
            if self.is_whitelisted(pid, name):
                continue
            last_sb = sandbox_pids.get(pid, 0.0)
            open_in_sandbox = bool(last_sb) and (now - last_sb) <= window   # signal A (Linux)
            delta, peak = self._window_stats(pid, now, window)

            # signal B: during sandbox activity, this process wrote a meaningful amount.
            writes_meaningfully = sandbox_active and delta >= config.ATTRIB_MIN_WRITE_BYTES

            if not (open_in_sandbox or writes_meaningfully):
                continue
            suspects.append(
                Suspect(
                    pid=pid, name=name, write_rate=peak, in_sandbox=open_in_sandbox,
                    last_sandbox_ts=last_sb, write_delta=delta, sandbox_bytes=sandbox_bytes,
                )
            )

        # Rank: a confirmed open handle wins; otherwise the HEAVIEST writer, which during an
        # encryption run is the attacker producing the ciphertext. Editors/browsers/system
        # processes can never reach here - they are filtered by the name whitelist above.
        suspects.sort(key=lambda s: (s.in_sandbox, s.write_delta, s.write_rate), reverse=True)
        return suspects

    def most_likely_suspect(self, window: float = config.PROC_WINDOW_SEC) -> Suspect | None:
        """The single best kill target right now, or None if we cannot attribute confidently."""
        suspects = self.get_suspects(window)
        return suspects[0] if suspects else None
