"""Kill switch CLI utility (root wrapper calling policy.killswitch)."""

from policy.killswitch import (
    activate_kill_switch,
    clear_kill_switch,
    is_kill_active,
    main,
)

if __name__ == "__main__":
    main()
