"""Kill switch utility managing data/KILL trigger file."""

import argparse
import os
from pathlib import Path

from core.paths import KILL_FILE_PATH


def is_kill_active(kill_file: str | Path = KILL_FILE_PATH) -> bool:
    """Checks if the data/KILL switch file exists."""
    return Path(kill_file).exists()


def activate_kill_switch(kill_file: str | Path = KILL_FILE_PATH) -> None:
    """Creates the data/KILL switch file."""
    kill_path = Path(kill_file)
    kill_path.parent.mkdir(parents=True, exist_ok=True)
    kill_path.write_text("KILL\n", encoding="utf-8")
    print(f"Kill switch activated: '{kill_path}' created.")


def clear_kill_switch(kill_file: str | Path = KILL_FILE_PATH) -> None:
    """Removes the data/KILL switch file if present."""
    kill_path = Path(kill_file)
    if kill_path.exists():
        kill_path.unlink()
        print(f"Kill switch cleared: '{kill_path}' removed.")
    else:
        print(f"Kill switch is not active: '{kill_path}' does not exist.")


def main():
    parser = argparse.ArgumentParser(description="Manage agent kill switch.")
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear the kill switch by removing data/KILL",
    )
    args = parser.parse_args()

    if args.clear:
        clear_kill_switch()
    else:
        activate_kill_switch()


if __name__ == "__main__":
    main()
