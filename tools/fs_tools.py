"""Read-only scoped filesystem tools powered by the local MCP filesystem server."""

import asyncio
import logging
from pathlib import Path
from typing import Any

from google.genai import types

from tools.fs_guard import (
    FSGuardError,
    WorkspaceSecurityError,
    truncate_result,
    validate_path,
)
from tools.fs_policy_map import FS_POLICY_MAP
from tools.mcp_client import FSMCPClient

logger = logging.getLogger(__name__)

# Singleton host variables
_client: FSMCPClient | None = None
_lock = asyncio.Lock()
_custom_workspace: str | Path | None = None


def set_custom_workspace(ws: str | Path | None) -> None:
    """Sets a custom workspace path, primarily for isolated test environments."""
    global _custom_workspace
    _custom_workspace = ws


def get_current_workspace() -> str | Path | None:
    """Returns the currently configured custom workspace, if any."""
    return _custom_workspace


async def get_client() -> FSMCPClient:
    """
    Lazy-starts and returns the singleton FSMCPClient instance.
    Safe for concurrent calls using asyncio.Lock.
    """
    global _client
    if _client is not None and _client.is_process_running():
        return _client

    async with _lock:
        if _client is not None and _client.is_process_running():
            return _client
        client = FSMCPClient(workspace=_custom_workspace)
        await client.__aenter__()
        _client = client
        return _client


async def shutdown() -> None:
    """Gracefully shuts down the singleton MCP server client process."""
    global _client
    async with _lock:
        if _client is not None:
            await _client.close()
            _client = None


async def _execute_mcp_tool(mcp_tool_name: str, args: dict[str, Any]) -> str:
    """
    Internal helper to call an MCP tool with 30s timeout, error shielding,
    and 20,000-character result truncation.
    """
    async def _invoke() -> str:
        client = await get_client()
        res = await client.call_tool(mcp_tool_name, args)
        texts = []
        if hasattr(res, "content") and res.content:
            for block in res.content:
                if hasattr(block, "text") and block.text:
                    texts.append(block.text)
                else:
                    texts.append(str(block))
        return "\n".join(texts)

    try:
        raw_result = await asyncio.wait_for(_invoke(), timeout=30.0)
        return truncate_result(raw_result, limit=20000)
    except asyncio.TimeoutError:
        return "tool error: timeout after 30 seconds"
    except Exception as e:
        global _client
        if _client is not None and not _client.is_process_running():
            _client = None
        return f"tool error: {e}"


# --- 7 Read-Only Filesystem Tool Wrappers ---


async def fs_read_text_file(
    path: str, head: int | None = None, tail: int | None = None
) -> str:
    """Reads complete or partial text contents of a file in the workspace."""
    try:
        resolved = validate_path(path, workspace=_custom_workspace, allow_root=False)
    except FSGuardError as e:
        return f"tool error: path denied: {e}"
    except Exception as e:
        return f"tool error: path denied: {e}"

    # Check 5 MB size limit on full-file read
    is_full_read = (head is None and tail is None)
    if is_full_read and resolved.is_file():
        try:
            size = resolved.stat().st_size
            if size > 5 * 1024 * 1024:
                return (
                    f"tool error: file size ({size} bytes) exceeds 5 MB limit for full-file read"
                )
        except OSError:
            pass

    args: dict[str, Any] = {"path": str(resolved)}
    if head is not None:
        args["head"] = int(head)
    if tail is not None:
        args["tail"] = int(tail)

    return await _execute_mcp_tool("read_text_file", args)


async def fs_read_multiple_files(paths: list[str]) -> str:
    """Reads multiple files from the workspace (max 10 paths)."""
    if not isinstance(paths, list):
        return "tool error: paths must be a list of strings"
    if len(paths) > 10:
        return f"tool error: requested {len(paths)} paths; maximum limit is 10"

    resolved_paths: list[str] = []
    for p in paths:
        try:
            resolved = validate_path(p, workspace=_custom_workspace, allow_root=False)
            if resolved.is_file():
                size = resolved.stat().st_size
                if size > 5 * 1024 * 1024:
                    return (
                        f"tool error: file '{resolved.name}' size ({size} bytes) "
                        "exceeds 5 MB limit for full-file read"
                    )
            resolved_paths.append(str(resolved))
        except FSGuardError as e:
            return f"tool error: path denied: {e}"
        except Exception as e:
            return f"tool error: path denied: {e}"

    return await _execute_mcp_tool("read_multiple_files", {"paths": resolved_paths})


async def fs_list_directory(path: str = ".") -> str:
    """Lists files and folders within a workspace directory."""
    try:
        resolved = validate_path(path, workspace=_custom_workspace, allow_root=True)
    except FSGuardError as e:
        return f"tool error: path denied: {e}"
    except Exception as e:
        return f"tool error: path denied: {e}"

    return await _execute_mcp_tool("list_directory", {"path": str(resolved)})


async def fs_list_directory_with_sizes(path: str = ".", sortBy: str = "name") -> str:
    """Lists directory contents with file sizes and optional sorting ('name' or 'size')."""
    try:
        resolved = validate_path(path, workspace=_custom_workspace, allow_root=True)
    except FSGuardError as e:
        return f"tool error: path denied: {e}"
    except Exception as e:
        return f"tool error: path denied: {e}"

    args: dict[str, Any] = {"path": str(resolved)}
    if sortBy:
        args["sortBy"] = sortBy
    return await _execute_mcp_tool("list_directory_with_sizes", args)


async def fs_directory_tree(
    path: str = ".", excludePatterns: list[str] | None = None
) -> str:
    """Returns a recursive tree view of files and directories as a JSON structure."""
    try:
        resolved = validate_path(path, workspace=_custom_workspace, allow_root=True)
    except FSGuardError as e:
        return f"tool error: path denied: {e}"
    except Exception as e:
        return f"tool error: path denied: {e}"

    args: dict[str, Any] = {"path": str(resolved)}
    if excludePatterns:
        args["excludePatterns"] = excludePatterns
    return await _execute_mcp_tool("directory_tree", args)


async def fs_search_files(
    path: str = ".", pattern: str = "*", excludePatterns: list[str] | None = None
) -> str:
    """Searches recursively for files matching a glob pattern."""
    try:
        resolved = validate_path(path, workspace=_custom_workspace, allow_root=True)
    except FSGuardError as e:
        return f"tool error: path denied: {e}"
    except Exception as e:
        return f"tool error: path denied: {e}"

    args: dict[str, Any] = {"path": str(resolved), "pattern": pattern}
    if excludePatterns:
        args["excludePatterns"] = excludePatterns
    return await _execute_mcp_tool("search_files", args)


async def fs_get_file_info(path: str) -> str:
    """Retrieves detailed metadata (size, timestamps, permissions) about a file or directory."""
    try:
        resolved = validate_path(path, workspace=_custom_workspace, allow_root=True)
    except FSGuardError as e:
        return f"tool error: path denied: {e}"
    except Exception as e:
        return f"tool error: path denied: {e}"

    return await _execute_mcp_tool("get_file_info", {"path": str(resolved)})


# --- Google GenAI Function Declarations ---

fs_read_text_file_schema = types.FunctionDeclaration(
    name="fs_read_text_file",
    description="Read the complete contents of a file from the workspace as text. Use head or tail to read partial lines.",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "path": types.Schema(type=types.Type.STRING, description="Path to the file to read."),
            "head": types.Schema(type=types.Type.INTEGER, description="Optional: read only first N lines."),
            "tail": types.Schema(type=types.Type.INTEGER, description="Optional: read only last N lines."),
        },
        required=["path"],
    ),
)

fs_read_multiple_files_schema = types.FunctionDeclaration(
    name="fs_read_multiple_files",
    description="Read multiple files from the workspace simultaneously. Maximum 10 paths permitted.",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "paths": types.Schema(
                type=types.Type.ARRAY,
                items=types.Schema(type=types.Type.STRING),
                description="Array of file paths to read (up to 10).",
            ),
        },
        required=["paths"],
    ),
)

fs_list_directory_schema = types.FunctionDeclaration(
    name="fs_list_directory",
    description="Get a detailed listing of files and directories in a workspace path.",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "path": types.Schema(type=types.Type.STRING, description="Directory path to list (default is workspace root '.')."),
        },
        required=["path"],
    ),
)

fs_list_directory_with_sizes_schema = types.FunctionDeclaration(
    name="fs_list_directory_with_sizes",
    description="Get a detailed listing of files and directories in a workspace path, including file sizes.",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "path": types.Schema(type=types.Type.STRING, description="Directory path to list."),
            "sortBy": types.Schema(type=types.Type.STRING, description="Sort entries by 'name' or 'size'."),
        },
        required=["path"],
    ),
)

fs_directory_tree_schema = types.FunctionDeclaration(
    name="fs_directory_tree",
    description="Get a recursive tree view of files and directories in the workspace as JSON structure.",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "path": types.Schema(type=types.Type.STRING, description="Root directory path for tree view."),
            "excludePatterns": types.Schema(
                type=types.Type.ARRAY,
                items=types.Schema(type=types.Type.STRING),
                description="Optional glob patterns to exclude from tree.",
            ),
        },
        required=["path"],
    ),
)

fs_search_files_schema = types.FunctionDeclaration(
    name="fs_search_files",
    description="Recursively search for files matching a glob pattern within the workspace.",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "path": types.Schema(type=types.Type.STRING, description="Directory path to search in."),
            "pattern": types.Schema(type=types.Type.STRING, description="Glob pattern (e.g. '*.txt' or '**/*.py')."),
            "excludePatterns": types.Schema(
                type=types.Type.ARRAY,
                items=types.Schema(type=types.Type.STRING),
                description="Optional glob patterns to exclude.",
            ),
        },
        required=["path", "pattern"],
    ),
)

fs_get_file_info_schema = types.FunctionDeclaration(
    name="fs_get_file_info",
    description="Retrieve metadata about a file or directory in the workspace (size, timestamps, permissions).",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={
            "path": types.Schema(type=types.Type.STRING, description="Path to file or directory."),
        },
        required=["path"],
    ),
)


def get_fs_tool_contracts():
    """Builds and returns ToolContract mapping for all 7 read-only filesystem tools."""
    from tools.registry import ToolContract

    wrappers = {
        "fs_read_text_file": (fs_read_text_file, fs_read_text_file_schema, "read_text_file"),
        "fs_read_multiple_files": (fs_read_multiple_files, fs_read_multiple_files_schema, "read_multiple_files"),
        "fs_list_directory": (fs_list_directory, fs_list_directory_schema, "list_directory"),
        "fs_list_directory_with_sizes": (fs_list_directory_with_sizes, fs_list_directory_with_sizes_schema, "list_directory_with_sizes"),
        "fs_directory_tree": (fs_directory_tree, fs_directory_tree_schema, "directory_tree"),
        "fs_search_files": (fs_search_files, fs_search_files_schema, "search_files"),
        "fs_get_file_info": (fs_get_file_info, fs_get_file_info_schema, "get_file_info"),
    }

    contracts = {}
    for model_name, (fn, schema, mcp_name) in wrappers.items():
        pol = FS_POLICY_MAP[mcp_name]
        contracts[model_name] = ToolContract(
            name=model_name,
            schema=schema,
            risk=pol.risk,
            reversible=pol.reversible,
            returns_untrusted=pol.returns_untrusted,
            function=fn,
        )
    return contracts
