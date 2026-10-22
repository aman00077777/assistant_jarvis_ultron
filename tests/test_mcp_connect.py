"""Unit tests for tools/mcp_client.py: connect, list_tools, process cleanup, env safety, and roots capability."""

import asyncio
import os
import re
import tempfile
import unittest
from pathlib import Path

from tools.mcp_client import FSMCPClient


class TestMCPConnect(unittest.IsolatedAsyncioTestCase):
    """Test suite for FSMCPClient connection, tool listing, isolation, and lifecycle."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(os.path.realpath(self.temp_dir.name))
        self.ws_dir = self.temp_path / "test_mcp_workspace"
        self.ws_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    # (a) connect + list_tools khaali nahi, and (d) roots capability declare nahi hui
    async def test_connect_and_list_tools(self):
        async with FSMCPClient(workspace=self.ws_dir) as client:
            tools = await client.list_tools()
            self.assertIsNotNone(tools)
            self.assertGreater(len(tools), 0, "list_tools should not be empty")

            tool_names = [tool.name for tool in tools]
            # Standard filesystem server exposes file manipulation tools
            expected_sample_tools = {"read_file", "write_file", "list_directory"}
            self.assertTrue(
                any(t in tool_names for t in expected_sample_tools),
                f"Expected tools not found in {tool_names}",
            )

            # (d) Verify roots capability is NOT declared
            self.assertIsNone(client.roots_capability, "Roots capability must be None")
            if client._session is not None:
                caps = client._session._build_capabilities(
                    client._session.protocol_version or "2025-11-25"
                )
                self.assertIsNone(caps.roots, "Roots capability in ClientCapabilities must be None")

    # (b) context exit ke baad server process maujood nahi
    async def test_process_cleanup_after_exit(self):
        client = FSMCPClient(workspace=self.ws_dir)
        async with client:
            self.assertTrue(client.is_process_running(), "Process should be running during context")
            pid = client.pid
            self.assertIsNotNone(pid, "Process PID must be recorded")

        # Give process termination a moment to settle
        await asyncio.sleep(0.3)
        self.assertFalse(
            client.is_process_running(),
            f"Process {pid} should not be running after context exit",
        )

    # (c) child ko jo env diya gaya usme koi KEY/TOKEN/SECRET/PASSWORD wala variable nahi
    def test_child_env_has_no_secrets(self):
        client = FSMCPClient(workspace=self.ws_dir)
        env = client.clean_env

        # Ensure essential keys exist
        self.assertIn("PATH", env, "Essential system variable PATH must be present")

        # Strictly verify no secret-like keys exist
        forbidden_patterns = ["KEY", "TOKEN", "SECRET", "PASSWORD"]
        for key in env:
            for pattern in forbidden_patterns:
                self.assertNotIn(
                    pattern,
                    key.upper(),
                    f"Forbidden secret pattern '{pattern}' found in environment variable '{key}'",
                )

        # Explicitly verify GEMINI_API_KEY is not leaked
        self.assertNotIn("GEMINI_API_KEY", env)


if __name__ == "__main__":
    unittest.main()
