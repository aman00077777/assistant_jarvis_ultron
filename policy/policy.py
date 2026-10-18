"""Security and execution policy for agent tools."""

import re
from typing import Any
from tools.registry import TOOL_REGISTRY, get_tool


def decide(
    tool_name: str,
    args: dict[str, Any] | None = None,
    risk: str | None = None,
    untrusted_seen: bool = False,
) -> str:
    """
    Determines execution policy for a tool call.
    Caller-provided risk is ignored; always uses risk from TOOL_REGISTRY contract.
    Returns: "allow", "allow_notify", "confirm", or "deny".

    Rules:
    - tool registry me nahi -> deny
    - low -> allow
    - medium -> allow_notify (lekin untrusted_seen True ho to confirm)
    - high -> confirm
    - unknown/invalid risk -> deny
    """
    # Use get_tool to ensure registry sync
    tool_contract = get_tool(tool_name) or TOOL_REGISTRY.get(tool_name)
    if not tool_contract:
        return "deny"

    # Always use the contract risk, ignoring the caller's risk parameter
    contract_risk = tool_contract.risk
    risk_lower = str(contract_risk).strip().lower() if contract_risk else ""

    if risk_lower == "low":
        return "allow"
    elif risk_lower == "medium":
        if untrusted_seen:
            return "confirm"
        return "allow_notify"
    elif risk_lower == "high":
        return "confirm"
    else:
        return "deny"


def _format_args_for_display(args: Any) -> str:
    """Formats args using repr(), removes control characters/newlines, and truncates to 300 chars."""
    raw = repr(args if args is not None else {})
    # Remove control characters (\x00-\x1f, \x7f-\x9f) including newlines, tabs, and escape sequences
    cleaned = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", raw)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if len(cleaned) > 300:
        cleaned = cleaned[:300] + "... [truncated]"
    return cleaned


def confirm_execution(tool_name: str, args: dict[str, Any] | None = None) -> bool:
    """
    Displays tool name and args on console and requests y/n confirmation.
    Default is 'n' (only 'y' allows execution).
    Args are displayed with repr(), control characters removed, and truncated to 300 chars.
    """
    args_display = _format_args_for_display(args)
    print(f"\n[CONFIRMATION REQUIRED]")
    print(f"Tool: {tool_name}")
    print(f"Args: {args_display}")
    try:
        choice = input("Allow execution? [y/N]: ").strip().lower()
        return choice == "y"
    except (KeyboardInterrupt, EOFError):
        print()
        return False
