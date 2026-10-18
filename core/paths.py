"""Project paths helper anchored to project root."""

from pathlib import Path

# Project root: core/paths.py -> parent is core/ -> parent of core/ is project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_DIR = PROJECT_ROOT / "data"
LOGS_DIR = PROJECT_ROOT / "logs"

KILL_FILE_PATH = DATA_DIR / "KILL"
AUDIT_LOG_PATH = LOGS_DIR / "audit.jsonl"
