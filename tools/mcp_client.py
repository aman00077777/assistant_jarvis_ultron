"""Async MCP client connecting to the scoped local filesystem MCP server."""

import json
import logging
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
import mcp_types as types

from core.paths import PROJECT_ROOT
from policy.killswitch import is_kill_active
from tools.fs_guard import resolve_workspace

logger = logging.getLogger(__name__)


def get_minimal_environment() -> dict[str, str]:
    """
    Returns a minimal, clean environment dict containing only essential
    system variables. Strips out any variable containing KEY, TOKEN,
    SECRET, or PASSWORD (case-insensitive).
    """
    allowed_keys = [
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "TEMP",
        "TMP",
        "COMSPEC",
        "APPDATA",
        "LOCALAPPDATA",
        "HOMEDRIVE",
        "HOMEPATH",
        "USERPROFILE",
        "PROCESSOR_ARCHITECTURE",
        "NUMBER_OF_PROCESSORS",
    ]
    env: dict[str, str] = {}
    for k in allowed_keys:
        v = os.environ.get(k)
        if v is not None:
            if not re.search(r"KEY|TOKEN|SECRET|PASSWORD", k, re.IGNORECASE):
                env[k] = v

    for k in list(env.keys()):
        if re.search(r"KEY|TOKEN|SECRET|PASSWORD", k, re.IGNORECASE):
            del env[k]

    return env


def get_server_entry_point() -> Path:
    """Reads the server entry path from the pinned filesystem MCP package.json."""
    pkg_json = (
        PROJECT_ROOT
        / "mcp_servers"
        / "node_modules"
        / "@modelcontextprotocol"
        / "server-filesystem"
        / "package.json"
    )
    if not pkg_json.exists():
        raise FileNotFoundError(f"MCP server package.json not found at {pkg_json}")
    with open(pkg_json, "r", encoding="utf-8") as f:
        data = json.load(f)
    bin_field = data.get("bin", {})
    if isinstance(bin_field, dict):
        rel = bin_field.get("mcp-server-filesystem") or next(iter(bin_field.values()))
    else:
        rel = bin_field
    entry = (pkg_json.parent / rel).resolve()
    if not entry.exists():
        raise FileNotFoundError(f"MCP server entry point not found at {entry}")
    return entry


class FSMCPClient:
    """
    Async context manager for connecting to the scoped Filesystem MCP server.
    Ensures safe execution, child process termination on exit/kill switch,
    and no leaked secrets or roots capabilities.
    """

    def __init__(self, workspace: str | Path | None = None):
        self.workspace = resolve_workspace(workspace)
        self.entry_point = get_server_entry_point()
        self.command = shutil.which("node") or "node"
        self.clean_env = get_minimal_environment()
        self.workspace_args = [str(self.workspace)]
        self.args = [str(self.entry_point), str(self.workspace)]

        self._stdio_cm = None
        self._session = None
        self.process = None
        self.pid: int | None = None

    @property
    def roots_capability(self) -> Any:
        """Returns roots capability; must be None as roots capability is disabled."""
        if self._session is not None:
            caps = self._session._build_capabilities(
                self._session._negotiated_version or "2025-11-25"
            )
            return caps.roots
        return None

    def is_process_running(self) -> bool:
        """Checks if the underlying MCP server child process is still running."""
        if self.process is None:
            return False
        if hasattr(self.process, "returncode") and self.process.returncode is not None:
            return False
        if self.pid is None:
            return False

        if sys.platform == "win32":
            try:
                import ctypes
                import ctypes.wintypes
                kernel32 = ctypes.windll.kernel32
                PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
                handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, self.pid)
                if not handle:
                    return False
                exit_code = ctypes.wintypes.DWORD()
                kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
                kernel32.CloseHandle(handle)
                STILL_ACTIVE = 259
                return exit_code.value == STILL_ACTIVE
            except Exception:
                return False
        else:
            try:
                os.kill(self.pid, 0)
                return True
            except OSError:
                return False

    async def __aenter__(self):
        if is_kill_active():
            raise RuntimeError("Kill switch is active; refusing to start MCP server.")

        server_params = StdioServerParameters(
            command=self.command,
            args=self.args,
            env=self.clean_env,
            cwd=str(PROJECT_ROOT / "mcp_servers"),
        )

        from mcp.client import stdio as stdio_mod
        orig_create_process = stdio_mod._create_platform_compatible_process

        async def _capturing_create_process(*p_args, **p_kwargs):
            proc = await orig_create_process(*p_args, **p_kwargs)
            self.process = proc
            self.pid = getattr(proc, "pid", None)
            return proc

        stdio_mod._create_platform_compatible_process = _capturing_create_process
        try:
            self._stdio_cm = stdio_client(server_params)
            read_stream, write_stream = await self._stdio_cm.__aenter__()
        finally:
            stdio_mod._create_platform_compatible_process = orig_create_process

        # Roots capability/callback BILKUL mat do: list_roots_callback=None
        self._session = ClientSession(
            read_stream=read_stream,
            write_stream=write_stream,
            list_roots_callback=None,
        )
        await self._session.__aenter__()
        await self._session.initialize()

        if is_kill_active():
            await self.close()
            raise RuntimeError("Kill switch is active; terminated MCP server.")

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def close(self):
        """Closes session and stops server process."""
        if self._session is not None:
            try:
                await self._session.__aexit__(None, None, None)
            except Exception as e:
                logger.debug(f"Error closing session: {e}")
            finally:
                self._session = None

        if self._stdio_cm is not None:
            try:
                await self._stdio_cm.__aexit__(None, None, None)
            except Exception as e:
                logger.debug(f"Error closing stdio transport: {e}")
            finally:
                self._stdio_cm = None

    async def list_tools(self) -> list[types.Tool]:
        """Lists raw tools available from the MCP server."""
        if self._session is None:
            raise RuntimeError("FSMCPClient is not connected. Use 'async with' context manager.")
        if is_kill_active():
            await self.close()
            raise RuntimeError("Kill switch is active; refusing to execute list_tools.")

        result = await self._session.list_tools()
        return result.tools
