"""Policy package."""

from policy.killswitch import (
    activate_kill_switch,
    clear_kill_switch,
    is_kill_active,
)
from policy.policy import confirm_execution, decide

__all__ = [
    "decide",
    "confirm_execution",
    "is_kill_active",
    "activate_kill_switch",
    "clear_kill_switch",
]
