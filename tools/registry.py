"""Tool registry and contract definitions."""

import os
from dataclasses import dataclass
from typing import Any, Callable
from google.genai import types

from tools.native.time_tool import get_current_time, get_current_time_schema


@dataclass
class ToolContract:
    name: str
    schema: types.FunctionDeclaration
    risk: str  # "low", "medium", "high"
    reversible: bool
    returns_untrusted: bool
    function: Callable[..., Any]


# Base registry: production tools
TOOL_REGISTRY: dict[str, ToolContract] = {
    "get_current_time": ToolContract(
        name="get_current_time",
        schema=get_current_time_schema,
        risk="low",
        reversible=True,
        returns_untrusted=False,
        function=get_current_time,
    ),
}


def _sync_test_tools() -> None:
    """Conditionally registers or unregisters test tools based on ASSISTANT_TEST."""
    if os.getenv("ASSISTANT_TEST") == "1":
        if "test_medium" not in TOOL_REGISTRY:
            from tools.native.test_tools import (
                test_faulty,
                test_faulty_schema,
                test_high,
                test_high_schema,
                test_medium,
                test_medium_schema,
                test_taint,
                test_taint_schema,
            )
            TOOL_REGISTRY["test_medium"] = ToolContract(
                name="test_medium",
                schema=test_medium_schema,
                risk="medium",
                reversible=True,
                returns_untrusted=False,
                function=test_medium,
            )
            TOOL_REGISTRY["test_high"] = ToolContract(
                name="test_high",
                schema=test_high_schema,
                risk="high",
                reversible=True,
                returns_untrusted=False,
                function=test_high,
            )
            TOOL_REGISTRY["test_taint"] = ToolContract(
                name="test_taint",
                schema=test_taint_schema,
                risk="low",
                reversible=True,
                returns_untrusted=True,
                function=test_taint,
            )
            TOOL_REGISTRY["test_faulty"] = ToolContract(
                name="test_faulty",
                schema=test_faulty_schema,
                risk="low",
                reversible=True,
                returns_untrusted=False,
                function=test_faulty,
            )
    else:
        TOOL_REGISTRY.pop("test_medium", None)
        TOOL_REGISTRY.pop("test_high", None)
        TOOL_REGISTRY.pop("test_taint", None)
        TOOL_REGISTRY.pop("test_faulty", None)


# Sync on module import
_sync_test_tools()


def get_tool(name: str) -> ToolContract | None:
    """Returns ToolContract for tool name if registered."""
    _sync_test_tools()
    return TOOL_REGISTRY.get(name)


def get_tool_declarations() -> list[types.FunctionDeclaration]:
    """Returns all FunctionDeclaration objects for registered tools."""
    _sync_test_tools()
    return [tool.schema for tool in TOOL_REGISTRY.values()]


def get_tools() -> list[types.Tool]:
    """Returns a list of Tool objects for Gemini API."""
    return [types.Tool(function_declarations=get_tool_declarations())]


def run_tool(name: str, args: dict[str, Any] | None = None) -> str:
    """
    Executes a tool from TOOL_REGISTRY by name with provided args.
    Unknown tool returns an error string instead of raising exception.
    No eval or exec is used anywhere.
    """
    _sync_test_tools()
    tool = TOOL_REGISTRY.get(name)
    if not tool:
        return f"Error: Tool '{name}' is not recognized."

    if not callable(tool.function):
        return f"Error: Tool '{name}' does not have a callable function."

    tool_args = args or {}
    try:
        result = tool.function(**tool_args)
        return str(result)
    except TypeError:
        # Fallback if function takes no arguments
        result = tool.function()
        return str(result)
