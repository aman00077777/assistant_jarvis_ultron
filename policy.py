"""Policy module (root wrapper for backward compatibility with policy package)."""

from policy.policy import confirm_execution, decide
from policy.killswitch import (
    activate_kill_switch,
    clear_kill_switch,
    is_kill_active,
)

__all__ = [
    "decide",
    "confirm_execution",
    "is_kill_active",
    "activate_kill_switch",
    "clear_kill_switch",
]
