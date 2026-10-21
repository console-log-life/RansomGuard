"""Makes the project root importable so `pytest` finds the `ransomguard` package."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
