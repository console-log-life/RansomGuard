"""
config.py

WHAT: one single place for every path, threshold and score weight used by RansomGuard.
WHY : during the demo we need to change one number (e.g. the alert threshold) and re-run
      an experiment. If those numbers were scattered across ten modules we could never
      explain or reproduce a result. Everything tunable lives here.
"""

from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------------------
# Paths. PROJECT_ROOT is the folder that contains the `ransomguard` package.
# ---------------------------------------------------------------------------
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent

SANDBOX: Path = PROJECT_ROOT / "sandbox"
PROTECTED_DIR: Path = SANDBOX / "protected"   # the only folder we ever watch/modify
BACKUP_DIR: Path = SANDBOX / ".backup"        # clean copies + manifest (ignored by watcher)
DEMO_DIR: Path = SANDBOX / "demo"             # scratch space for demo_entropy.py

BASELINE_FILE: Path = SANDBOX / "baseline.json"
MANIFEST_FILE: Path = BACKUP_DIR / "manifest.json"
CANARY_FILE: Path = SANDBOX / "canaries.json"
SIM_KEY_FILE: Path = SANDBOX / "sim_key.bin"  # simulator's AES key, so we can always undo
# Key that protects the backup (AES-256-GCM) and signs the manifest (HMAC-SHA256). It lives
# in a file inside the sandbox for this student project; IN A REAL DEPLOYMENT this key would
# be held by the OS keystore / a TPM / an HSM, never on the same disk as the backup it
# protects. Two independent subkeys are derived from it (see backup.py).
BACKUP_KEY_FILE: Path = SANDBOX / "backup_key.bin"
LOG_FILE: Path = SANDBOX / "events.jsonl"
RESULTS_DIR: Path = PROJECT_ROOT / "evaluation" / "results"

# ---------------------------------------------------------------------------
# Entropy / randomness thresholds
# ---------------------------------------------------------------------------
ENTROPY_SAMPLE_BYTES: int = 65536   # only read the first 64 KB of a file (fast enough live)
HIGH_ENTROPY: float = 7.5           # >= this (out of 8.0) means "looks encrypted/compressed"
ENTROPY_JUMP: float = 2.0           # a rise this large vs the baseline is suspicious

# Chi-square against a uniform distribution over 256 byte values has 255 degrees of
# freedom, so *truly random* bytes score around 255 and almost never above ~500.
# Text/CSV/JSON score in the tens of thousands. So a LOW chi-square = looks random.
CHI_SQUARE_RANDOM_MAX: float = 500.0

# ---------------------------------------------------------------------------
# Score weights (used by scorer.py, phase 3+)
# ---------------------------------------------------------------------------
W_ENTROPY_JUMP: int = 30     # entropy rose > ENTROPY_JUMP and is now > HIGH_ENTROPY
W_MAGIC_BROKEN: int = 20     # a .pdf that no longer starts with %PDF, etc.
W_LOW_CHI_SQUARE: int = 10   # byte distribution became uniform
W_CANARY: int = 60           # a canary/honey file was touched -> almost certainly malicious
W_SUSPICIOUS_EXT: int = 15   # renamed to .locked/.enc/... or to an unknown new extension
W_BURST: int = 20            # many modifications in a few seconds

BACKUP_REFRESH_SEC: float = 10.0   # how often to refresh the backup with clean file edits
SCORE_THRESHOLD: int = 70          # act (suspend + stop) at or above this score
SCORE_HALF_LIFE_SEC: float = 30.0  # scores halve every 30 s so normal work cannot pile up
BURST_WINDOW_SEC: float = 5.0
BURST_COUNT: int = 20

SUSPICIOUS_EXTS: frozenset[str] = frozenset(
    {".locked", ".enc", ".crypt", ".encrypted", ".crypted", ".cry", ".ryk", ".wncry"}
)

# ---------------------------------------------------------------------------
# Process monitor (phase 4)
# ---------------------------------------------------------------------------
PROC_SAMPLE_INTERVAL: float = 0.3     # seconds between psutil io_counters samples
PROC_WINDOW_SEC: float = 5.0          # how far back "recently active in sandbox" looks
PROC_MIN_WRITE_RATE: int = 64 * 1024  # bytes/s below which a process is not a suspect

# Never suspend/stop these, whatever the score says. Names are matched case-insensitively
# and with any ".exe" suffix stripped (see ProcessMonitor.is_whitelisted), so "code" here
# matches "Code.exe" on Windows and "code" on Linux. This is a safety net; the real
# attribution tie is write-volume correlation, not the name.
PROTECTED_PROC_NAMES: frozenset[str] = frozenset(
    {
        # unix / shells / dev tools
        "systemd", "init", "kthreadd", "sshd", "bash", "sh", "zsh", "dash",
        "gnome-shell", "xorg", "dbus-daemon", "code", "pytest", "streamlit",
        # editors / browsers that legitimately write a lot
        "chrome", "msedge", "firefox", "node",
        # windows shell / service host processes
        "explorer", "powershell", "pwsh", "cmd", "conhost", "system",
        "svchost", "services", "lsass", "winlogon", "csrss", "wininit", "smss",
        "dwm", "taskhostw", "runtimebroker", "sihost", "ctfmon", "fontdrvhost",
        "searchindexer", "searchhost", "searchprotocolhost", "searchfilterhost",
        "startmenuexperiencehost", "textinputhost", "audiodg", "spoolsv",
        "msmpeng", "securityhealthservice", "shellexperiencehost",
        # kernel / pseudo processes that can show high I/O but are not real user processes
        "registry", "memcompression", "secure system", "system idle process",
        "msedgewebview2", "msedge", "widgets", "wmiprvse",
    }
)

# Behaviour-based attribution (signal B): while the sandbox is actively changing, the
# culprit is the non-whitelisted process writing the most. We require the candidate to have
# written at least this many bytes in the window (so trivial writers are ignored) and we
# rank by write volume, so the heaviest writer - the one producing the ciphertext - wins.
# The sandbox byte volume is still recorded (for the log and as a sanity check) but is not a
# hard gate, because Windows write-buffering can make a process's write_bytes lag the
# sandbox growth. The name whitelist above, not this rule, is what protects editors/system.
ATTRIB_MIN_WRITE_BYTES: int = 32 * 1024
ATTRIB_MIN_SANDBOX_BYTES: int = 4096   # ignore trivial sandbox changes
ATTRIB_TIMEOUT_SEC: float = 6.0        # how long to keep trying to attribute after an alert
# NOTE: attribution is purely behaviour-based - write-rate spike correlated with sandbox
# file activity, confirmed by open files in the sandbox. We deliberately do NOT identify a
# process by its name or command line, so renaming the attacker does not evade detection.

USE_FANOTIFY: bool = False  # optional kernel-level PID attribution (Linux only)

# open_files() as an attribution confirmation (signal A). OFF by default because on Windows
# it both misses the simulator's quick-open/close handles AND can block the sampler on busy
# system processes. On Linux it is reliable and cheap, so it can be turned on there.
ATTRIB_USE_OPEN_FILES: bool = False

# ---------------------------------------------------------------------------
# Canary files (phase 3)
# ---------------------------------------------------------------------------
# "aaa_" names get hit first and "zzz_" names last by an alphabetical crawler, so
# whichever order the simulator walks the folder in, it steps on one of them early.
CANARY_NAMES: tuple[str, ...] = (
    "aaa_DO_NOT_MODIFY_passwords.txt",
    "aaa_account_backup.csv",
    "zzz_tax_return_2024.txt",
    "zzz_wallet_notes.txt",
)

# ---------------------------------------------------------------------------
# Safety guard
# ---------------------------------------------------------------------------


class SandboxViolation(Exception):
    """Raised when any component is asked to touch a path outside the sandbox."""


def ensure_inside(path: Path, root: Path | None = None) -> Path:
    """
    Resolve `path` and make sure it is inside `root` (default: the sandbox).

    Every write/delete in this project goes through here. It is the one hard safety
    rule: the detector, the recovery code and especially the simulator must not be
    able to touch a single byte outside ./sandbox.
    """
    root = (root or SANDBOX).resolve()
    resolved = Path(path).resolve()
    if resolved != root and root not in resolved.parents:
        raise SandboxViolation(f"{resolved} is outside the sandbox ({root})")
    return resolved
