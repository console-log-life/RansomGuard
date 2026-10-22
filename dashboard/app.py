"""
app.py  (Streamlit dashboard)

WHAT: a live view of what the monitor is doing, read straight from the JSON-lines event log
      (./sandbox/events.jsonl). It shows the current suspicion score and threshold, any
      alerts and the response taken (culprit PID, suspend, kill), how many files were
      encrypted and how many were restored, the canary status, and a scrolling feed of
      recent file events with the signals that fired.

WHY : the console log is great for the evaluation but hard to read while demoing. This
      dashboard turns the same log into something a professor can watch in real time: start
      it, run the simulator in another terminal, and watch the score climb, the alert fire,
      and the files get restored. It only READS the log - it never touches the sandbox or
      the detector - so it is completely safe to leave running.

Run:  streamlit run dashboard/app.py
      (start the monitor with --enforce in one terminal and the simulator in another)
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ransomguard import config
from ransomguard.logger import read_events

st.set_page_config(page_title="RansomGuard", page_icon="shield", layout="wide")


def load() -> list[dict]:
    try:
        return read_events(config.LOG_FILE)
    except (OSError, ValueError):
        return []


def by_event(events: list[dict], name: str) -> list[dict]:
    return [e for e in events if e.get("event") == name]


# --------------------------------------------------------------------- sidebar
st.sidebar.title("RansomGuard")
st.sidebar.caption("Real-time ransomware detection & recovery")
auto = st.sidebar.checkbox("Auto-refresh (2 s)", value=True)
st.sidebar.write(f"Log file:\n`{config.LOG_FILE}`")
if st.sidebar.button("Refresh now"):
    st.rerun()

events = load()
startup = by_event(events, "startup")
alerts = by_event(events, "ALERT")
fs_events = by_event(events, "fs_event")
recoveries = by_event(events, "recovery")
kills = by_event(events, "kill")
culprits = by_event(events, "culprit")

# --------------------------------------------------------------------- header
st.title("RansomGuard - live monitor")
if not events:
    st.info(
        "No events yet. Start the monitor and run the simulator:\n\n"
        "```\npython -m ransomguard.monitor --enforce\n"
        "python -m simulator.fake_ransomware --delay 0.2\n```"
    )
    if auto:
        time.sleep(2)
        st.rerun()
    st.stop()

last = events[-1]
mode = "ENFORCING" if (startup and startup[-1].get("enforce")) else "log-only"
watched = startup[-1].get("path", "?") if startup else "?"
status = "UNDER ATTACK" if alerts else "clean"
st.caption(f"mode: **{mode}**  |  watching: `{watched}`  |  last event: {last.get('iso','?')}")

# --------------------------------------------------------------------- metrics
current_score = fs_events[-1].get("score", 0) if fs_events else 0
canary_total = startup[-1].get("canaries", 0) if startup else 0
canary_hits = sum(1 for e in fs_events if e.get("canary"))
affected = recoveries[-1].get("affected", 0) if recoveries else 0
restored = recoveries[-1].get("restored", 0) if recoveries else 0

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Suspicion score", f"{current_score}", help=f"threshold = {config.SCORE_THRESHOLD}")
c2.metric("Status", status)
c3.metric("Files encrypted", affected)
c4.metric("Files restored", f"{restored}/{affected}" if affected else "0")
c5.metric("Canaries", f"{canary_total - canary_hits}/{canary_total} intact")

if alerts:
    st.error(f"ALERT raised - score {alerts[-1].get('score')} - "
             f"reasons: {', '.join(alerts[-1].get('reasons', []))}")
else:
    st.success("No alerts. Folder looks clean.")

# --------------------------------------------------------- response + score
left, right = st.columns([1, 1])

with left:
    st.subheader("Response")
    if culprits or kills or recoveries:
        if culprits:
            c = culprits[-1]
            st.write(f"**Culprit:** PID `{c.get('pid')}` ({c.get('name')}), "
                     f"write rate {c.get('write_rate', 0):,} B/s")
        if kills:
            st.write(f"**Killed:** PID `{kills[-1].get('pid')}` ({kills[-1].get('name')})")
        if recoveries:
            r = recoveries[-1]
            st.write(f"**Recovered:** {r.get('restored')} restored, "
                     f"{r.get('failed')} failed, {r.get('removed_artifacts')} artifacts removed")
    else:
        st.write("No response yet.")

with right:
    st.subheader("Score over time")
    scores = [e.get("score", 0) for e in fs_events]
    if scores:
        st.line_chart(scores, height=220)
    else:
        st.write("No scored events yet.")

# ------------------------------------------------------------- event feed
st.subheader("Recent file events")
rows = []
for e in reversed(fs_events[-200:]):
    rows.append(
        {
            "time": e.get("iso", "").split("T")[-1],
            "kind": e.get("kind"),
            "path": e.get("path"),
            "entropy": e.get("entropy"),
            "magic_ok": e.get("magic_ok"),
            "canary": e.get("canary"),
            "signals": ", ".join(e.get("reasons", [])),
            "+pts": e.get("points"),
            "score": e.get("score"),
        }
    )
if rows:
    st.dataframe(rows, use_container_width=True, height=360)
else:
    st.write("No file events yet.")

if auto:
    time.sleep(2)
    st.rerun()
