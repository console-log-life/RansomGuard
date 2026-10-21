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
PROC_SAMPLE_INTERVAL: float = 0.5     # seconds between psutil io_counters samples
PROC_WINDOW_SEC: float = 5.0          # how far back "recently active in sandbox" looks
PROC_MIN_WRITE_RATE: int = 64 * 1024  # bytes/s below which a process is not a suspect

# Never suspend/stop these, whatever the score says.
PROTECTED_PROC_NAMES: frozenset[str] = frozenset(
    {
        "systemd", "init", "kthreadd", "sshd", "bash", "sh", "zsh", "dash",
        "gnome-shell", "Xorg", "dbus-daemon", "code", "pytest", "streamlit",
        "explorer.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "System",
    }
)
# The simulator is a python process like ours, so we identify it by its script name.
SIMULATOR_HINT: str = "fake_ransomware"

USE_FANOTIFY: bool = False  # optional kernel-level PID attribution (Linux only, phase 4)

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
