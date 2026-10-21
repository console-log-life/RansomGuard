"""
test_responder.py

WHAT: tests process attribution (process_monitor) and the suspend/kill response
      (responder) against REAL, harmless subprocesses we spawn and clean up.

WHY : these are the only parts of the project that reach out and change OS state (freezing
      and killing processes), so they are the most important to test carefully and the most
      dangerous to get wrong. The tests prove two opposite guarantees:
        * it DOES stop a process that writes hard inside the sandbox, and
        * it REFUSES to touch our own process or anything whitelisted.
      We only ever spawn disposable helper processes; nothing real is harmed.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time

import psutil
import pytest

from ransomguard import config
from ransomguard.logger import EventLogger
from ransomguard.process_monitor import ProcessMonitor
from ransomguard.responder import Responder


# On Windows the venv's python.exe is a LAUNCHER that re-spawns the real interpreter as a
# child with a different PID. So subprocess.Popen(...).pid is not the PID that actually runs
# our code. Each helper therefore has the child write its own os.getpid() to a pidfile, and
# we return that real worker PID - the same PID the monitor attributes and the simulator
# prints. Cleanup kills the whole tree so no worker leaks between tests.
def _real_pid(popen: subprocess.Popen, pidfile) -> int:
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            return int(pidfile.read_text())
        except (OSError, ValueError):
            time.sleep(0.05)
    raise RuntimeError("worker never reported its PID")


def _spawn_sleeper(tmp_path) -> tuple[subprocess.Popen, int]:
    pidfile = tmp_path / "sleeper.pid"
    code = f"import os,time;open(r'{pidfile}','w').write(str(os.getpid()));time.sleep(60)"
    popen = subprocess.Popen([sys.executable, "-c", code])
    return popen, _real_pid(popen, pidfile)


def _spawn_writer(target_dir, pidfile) -> tuple[subprocess.Popen, int]:
    code = textwrap.dedent(
        f"""
        import os, time
        open(r"{pidfile}", "w").write(str(os.getpid()))
        p = os.path.join(r"{target_dir}", "busy.bin")
        end = time.time() + 6
        with open(p, "wb") as f:
            while time.time() < end:
                f.write(os.urandom(262144))
                f.flush(); os.fsync(f.fileno())
                time.sleep(0.05)
        """
    )
    popen = subprocess.Popen([sys.executable, "-c", code])
    return popen, _real_pid(popen, pidfile)


def _cleanup(*pids_or_popens) -> None:
    """Kill each given PID/Popen and all descendants, so nothing lingers."""
    for item in pids_or_popens:
        pid = item.pid if isinstance(item, subprocess.Popen) else item
        try:
            proc = psutil.Process(pid)
            for child in proc.children(recursive=True):
                try:
                    child.resume(); child.kill()
                except psutil.Error:
                    pass
            proc.resume(); proc.kill()
        except psutil.Error:
            pass


# --------------------------------------------------------------- responder
def test_suspend_then_kill_stops_a_process(tmp_path):
    proc, pid = _spawn_sleeper(tmp_path)
    try:
        responder = Responder(EventLogger(echo=False))
        resp = responder.suspend(pid)
        assert resp.suspended is True
        assert psutil.pid_exists(pid)               # suspended, not yet gone

        responder.kill(resp)
        assert resp.killed is True
        time.sleep(0.3)
        # Either the PID is gone, or it is a reaped zombie (both mean "stopped").
        assert (not psutil.pid_exists(pid)) or psutil.Process(pid).status() == psutil.STATUS_ZOMBIE
    finally:
        _cleanup(proc, pid)


def test_respond_all_in_one_path(tmp_path):
    proc, pid = _spawn_sleeper(tmp_path)
    try:
        responder = Responder(EventLogger(echo=False))
        resp = responder.respond(pid, kill_now=True)
        assert resp.suspended and resp.killed and not resp.refused
    finally:
        _cleanup(proc, pid)


def test_responder_refuses_to_kill_own_process():
    # The most important safety test: we must never be able to kill ourselves.
    pm = ProcessMonitor(config.SANDBOX)
    responder = Responder(EventLogger(echo=False), pm)
    resp = responder.respond(os.getpid())
    assert resp.refused
    assert not resp.suspended and not resp.killed


def test_responder_refuses_whitelisted_name(tmp_path, monkeypatch):
    proc, pid = _spawn_sleeper(tmp_path)
    try:
        pm = ProcessMonitor(config.SANDBOX)
        # Pretend the sleeper's name is whitelisted, so the responder must decline.
        monkeypatch.setattr(pm, "is_whitelisted", lambda p, name: p == pid)
        responder = Responder(EventLogger(echo=False), pm)
        resp = responder.respond(pid)
        assert resp.refused == "protected/whitelisted"
        assert psutil.pid_exists(pid)               # untouched
    finally:
        _cleanup(proc, pid)


def test_responder_handles_already_dead_process(tmp_path):
    proc, pid = _spawn_sleeper(tmp_path)
    _cleanup(proc, pid)
    time.sleep(0.3)
    responder = Responder(EventLogger(echo=False))
    resp = responder.suspend(pid)
    assert resp.refused  # no such process, declined cleanly (no crash)


# ----------------------------------------------------- process attribution
def test_process_monitor_attributes_sandbox_writer(tmp_path):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    pm = ProcessMonitor(sandbox, interval=0.2)
    pm.start()
    writer, worker_pid = _spawn_writer(sandbox, tmp_path / "writer.pid")
    try:
        # Give the sampler time to attribute the worker (by command line / open file).
        suspect = None
        deadline = time.time() + 6
        while time.time() < deadline:
            if any(s.pid == worker_pid for s in pm.get_suspects()):
                suspect = next(s for s in pm.get_suspects() if s.pid == worker_pid)
                break
            time.sleep(0.2)
        assert suspect is not None, "writer worker was never attributed as a suspect"
        assert suspect.in_sandbox is True
    finally:
        pm.stop()
        _cleanup(writer, worker_pid)


def test_process_monitor_never_lists_itself(tmp_path):
    pm = ProcessMonitor(tmp_path, interval=0.2)
    assert pm.is_whitelisted(os.getpid(), "python.exe") is True
    pm.start()
    try:
        time.sleep(0.6)
        assert all(s.pid != os.getpid() for s in pm.get_suspects())
    finally:
        pm.stop()
