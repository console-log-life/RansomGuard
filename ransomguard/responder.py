"""
responder.py

WHAT: the "stop the attack" action. Given a PID it suspends the process first, logs the
      alert with a precise detection timestamp, then terminates and (if needed) kills it.

WHY : once the score says "this is ransomware", speed matters - every extra file encrypted
      is a file we may not get back. We SUSPEND before killing for two reasons:
        1. it freezes the damage instantly (a suspended process writes nothing), and
        2. it leaves the process in a known-stopped state while recovery (phase 5) runs,
           so it cannot race us by encrypting more files as we restore them.
      Only after recovery do we actually kill it. The detection time we record here is the
      number the evaluation (phase 6) reports as "time to stop".

SAFETY: respond() refuses point-blank to touch a whitelisted or protected PID (our own
process, the launching shell, system services). There is no code path that kills those.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import psutil

from .logger import EventLogger
from .process_monitor import ProcessMonitor


@dataclass
class Response:
    pid: int
    name: str = ""
    suspended: bool = False
    killed: bool = False
    detected_at: float = 0.0        # epoch time the alert was raised
    refused: str = ""               # non-empty if we declined to act (and why)
    history: list[str] = field(default_factory=list)


class Responder:
    """Suspends, then (after recovery) kills, a process identified as ransomware."""

    def __init__(self, logger: EventLogger, proc_monitor: ProcessMonitor | None = None) -> None:
        self.logger = logger
        self.proc_monitor = proc_monitor

    def _is_protected(self, pid: int, name: str) -> bool:
        if self.proc_monitor is not None:
            return self.proc_monitor.is_whitelisted(pid, name)
        from . import config

        return name in config.PROTECTED_PROC_NAMES

    def suspend(self, pid: int) -> Response:
        """
        Freeze the process immediately and record the detection time. This is the first,
        most urgent action; killing can wait until after recovery has run.
        """
        detected_at = time.time()
        try:
            proc = psutil.Process(pid)
            name = proc.name()
        except psutil.Error as exc:
            resp = Response(pid=pid, detected_at=detected_at, refused=f"no such process: {exc}")
            self.logger.log("respond_refused", pid=pid, reason=resp.refused)
            return resp

        if self._is_protected(pid, name):
            resp = Response(pid=pid, name=name, detected_at=detected_at, refused="protected/whitelisted")
            self.logger.log("respond_refused", pid=pid, name=name, reason="protected/whitelisted")
            return resp

        resp = Response(pid=pid, name=name, detected_at=detected_at)
        try:
            proc.suspend()
            resp.suspended = True
            resp.history.append("suspended")
            self.logger.log("suspend", pid=pid, name=name, detected_at=round(detected_at, 3))
        except psutil.Error as exc:
            resp.history.append(f"suspend failed: {exc}")
            self.logger.log("suspend_failed", pid=pid, name=name, error=str(exc))
        return resp

    def kill(self, resp: Response, grace: float = 2.0) -> Response:
        """
        Terminate the (already suspended) process, escalating to kill if it lingers.

        A suspended process may ignore SIGTERM until resumed, so we resume-then-terminate,
        wait briefly, and hard-kill if it is still alive.
        """
        if resp.refused:
            return resp
        try:
            proc = psutil.Process(resp.pid)
        except psutil.Error:
            resp.killed = True                      # already gone counts as stopped
            resp.history.append("already exited")
            return resp
        try:
            if resp.suspended:
                proc.resume()                       # let it receive the signal, then die
            proc.terminate()
            try:
                proc.wait(timeout=grace)
            except psutil.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=grace)
            resp.killed = True
            resp.history.append("killed")
            self.logger.log("kill", pid=resp.pid, name=resp.name)
        except psutil.NoSuchProcess:
            resp.killed = True
            resp.history.append("exited during kill")
        except psutil.Error as exc:
            resp.history.append(f"kill failed: {exc}")
            self.logger.log("kill_failed", pid=resp.pid, name=resp.name, error=str(exc))
        return resp

    def respond(self, pid: int, kill_now: bool = True, grace: float = 2.0) -> Response:
        """
        Full response: suspend, then (unless kill_now is False) kill.

        The live monitor calls respond(pid, kill_now=False) so recovery can run while the
        process is frozen, then calls kill() afterwards. kill_now=True is the simple
        all-in-one path used when there is nothing to recover (and by tests).
        """
        resp = self.suspend(pid)
        if resp.refused or not resp.suspended:
            return resp
        if kill_now:
            resp = self.kill(resp, grace=grace)
        return resp
