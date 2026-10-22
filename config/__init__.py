"""Configuration loader for the assistant."""

import os

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore

SETTINGS_FILE = os.path.join(os.path.dirname(__file__), "settings.toml")


def load_settings(file_path: str = SETTINGS_FILE) -> dict:
    """Loads configuration settings from TOML file using tomllib."""
    if os.path.exists(file_path):
        with open(file_path, "rb") as f:
            return tomllib.load(f)
    return {
        "workspace_dir": r"C:\dev\assistant-workspace",
        "orchestrator": {"max_steps": 5},
    }


def get_max_steps() -> int:
    """Returns max_steps configured for orchestrator."""
    settings = load_settings()
    return settings.get("orchestrator", {}).get("max_steps", 5)


def get_workspace_dir(file_path: str = SETTINGS_FILE) -> str:
    """Returns workspace_dir configured in settings."""
    settings = load_settings(file_path)
    return str(
        settings.get("workspace_dir")
        or settings.get("workspace", {}).get("workspace_dir")
        or r"C:\dev\assistant-workspace"
    )

