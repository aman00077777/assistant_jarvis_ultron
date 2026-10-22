"""Acceptance test suite for scoped read-only filesystem tools (Phase 1, Step 4)."""

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from google.genai import types

from core.orchestrator import Orchestrator
from core.paths import AUDIT_LOG_PATH, PROJECT_ROOT
from core.provider import BaseLLMProvider
from policy.killswitch import activate_kill_switch, clear_kill_switch
from policy.policy import decide
from tools.fs_guard import WorkspaceSecurityError
from tools.fs_tools import (
    fs_directory_tree,
    fs_get_file_info,
    fs_list_directory,
    fs_list_directory_with_sizes,
    fs_read_multiple_files,
    fs_read_text_file,
    fs_search_files,
    set_custom_workspace,
    shutdown,
)
from tools.registry import (
    TOOL_REGISTRY,
    _sync_fs_tools,
    get_tool,
    run_tool_async,
)

IS_LIVE = "--live" in sys.argv


class MockProvider(BaseLLMProvider):
    """Deterministic mock provider for unit tests without network/API quota."""

    def __init__(
        self,
        tool_to_call: str | None = None,
        args: dict[str, Any] | None = None,
        final_text: str = "Executed successfully",
    ):
        self.tool_to_call = tool_to_call
        self.args = args or {}
        self.final_text = final_text
        self.call_count = 0

    async def generate(self, messages: list[Any], tools: list[Any] | None = None) -> Any:
        self.call_count += 1
        if self.call_count == 1 and self.tool_to_call:
            part = types.Part.from_function_call(name=self.tool_to_call, args=self.args)
            content = types.Content(role="model", parts=[part])
            candidate = types.Candidate(content=content)
            return types.GenerateContentResponse(candidates=[candidate])
        else:
            part = types.Part.from_text(text=self.final_text)
            content = types.Content(role="model", parts=[part])
            candidate = types.Candidate(content=content)
            return types.GenerateContentResponse(candidates=[candidate])


def read_latest_audit_logs(limit: int = 10) -> list[dict]:
    log_file = str(AUDIT_LOG_PATH)
    if not os.path.exists(log_file):
        return []
    with open(log_file, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
    results = []
    for line in lines[-limit:]:
        try:
            results.append(json.loads(line))
        except Exception:
            pass
    return results


class TestFSTools(unittest.IsolatedAsyncioTestCase):
    """Acceptance test suite for read-only filesystem tools."""

    async def asyncSetUp(self):
        # Create an isolated temporary directory for testing outside project root
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(os.path.realpath(self.temp_dir.name))
        self.ws_dir = self.temp_path / "test_fs_workspace"
        self.ws_dir.mkdir(parents=True, exist_ok=True)
        set_custom_workspace(self.ws_dir)
        _sync_fs_tools()

    async def asyncTearDown(self):
        # Safely shutdown client and cleanup
        await shutdown()
        set_custom_workspace(None)
        _sync_fs_tools()
        junction_path = self.ws_dir / "junction_outside"
        if junction_path.exists():
            try:
                os.rmdir(junction_path)
            except Exception:
                pass
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    # a) workspace project ke andar -> fs tools register na hon
    async def test_workspace_inside_project_disables_fs_tools(self):
        set_custom_workspace(PROJECT_ROOT / "sub_folder_test")
        _sync_fs_tools()
        self.assertIsNone(get_tool("fs_read_text_file"))
        self.assertNotIn("fs_read_text_file", TOOL_REGISTRY)
        self.assertNotIn("fs_list_directory", TOOL_REGISTRY)

        # Restore workspace for subsequent tests
        set_custom_workspace(self.ws_dir)
        _sync_fs_tools()
        self.assertIsNotNone(get_tool("fs_read_text_file"))

    # b) workspace ki file read -> content mile, audit me requested + allow, aur session tainted
    async def test_read_file_works_and_taints_session(self):
        sample_file = self.ws_dir / "hello.txt"
        sample_file.write_text("Secret content inside workspace", encoding="utf-8")

        session_id = "test-fs-session-b"
        provider = MockProvider(
            tool_to_call="fs_read_text_file",
            args={"path": "hello.txt"},
            final_text="I read the file successfully",
        )
        orch = Orchestrator(session_id=session_id, provider=provider)
        response = await orch.run_turn("Read hello.txt")

        # Session should become tainted because returns_untrusted=True
        self.assertTrue(orch.untrusted_seen, "Session should be tainted after reading file")

        # Audit log verification: must contain 'requested' and 'allow'
        logs = read_latest_audit_logs(limit=10)
        tool_logs = [log for log in logs if log.get("tool") == "fs_read_text_file"]
        decisions = [log.get("decision") for log in tool_logs]
        self.assertIn("requested", decisions, "Audit log must contain 'requested' event")
        self.assertIn("allow", decisions, "Audit log must contain 'allow' decision")

    # c) "..\..\.env", C:\Windows\win.ini, UNC, "file.txt:stream", junction se bahar -> sab denied
    async def test_denied_paths(self):
        # 1. Traversal escaping workspace
        res1 = await fs_read_text_file(r"..\..\.env")
        self.assertIn("tool error: path denied", res1)

        # 2. Outside absolute path
        res2 = await fs_read_text_file(r"C:\Windows\win.ini")
        self.assertIn("tool error: path denied", res2)

        # 3. UNC path
        res3 = await fs_read_text_file(r"\\server\share\file.txt")
        self.assertIn("tool error: path denied", res3)

        # 4. Alternate data stream
        res4 = await fs_read_text_file("file.txt:stream")
        self.assertIn("tool error: path denied", res4)

        # 5. Junction pointing outside
        outside_dir = self.temp_path / "outside_dir"
        outside_dir.mkdir(parents=True, exist_ok=True)
        secret_file = outside_dir / "secret.txt"
        secret_file.write_text("Outside secret!", encoding="utf-8")
        junction_path = self.ws_dir / "junction_outside"

        if os.name == "nt":
            cmd = f'cmd /c mklink /J "{junction_path}" "{outside_dir}"'
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if proc.returncode == 0:
                res5 = await fs_read_text_file(str(junction_path / "secret.txt"))
                self.assertIn("tool error: path denied", res5)

        # 6. Verify audit log captures denied path through Orchestrator
        session_id_deny = "test-fs-session-deny"
        provider_deny = MockProvider(
            tool_to_call="fs_read_text_file",
            args={"path": r"..\..\.env"},
            final_text="Blocked path",
        )
        orch = Orchestrator(session_id=session_id_deny, provider=provider_deny)
        await orch.run_turn(r"Read ..\..\.env")
        logs = read_latest_audit_logs(limit=5)
        deny_logs = [
            log for log in logs
            if log.get("session_id") == session_id_deny and log.get("tool") == "fs_read_text_file"
        ]
        self.assertTrue(len(deny_logs) > 0, "Audit log must contain denied tool call")
        self.assertTrue(any("path denied" in str(log.get("result", "")) for log in deny_logs))

    # d) read_multiple_files me ek bura path -> poori call deny
    async def test_read_multiple_files_atomicity_and_limits(self):
        good_file = self.ws_dir / "good.txt"
        good_file.write_text("Valid content", encoding="utf-8")

        # One bad path denies the entire call
        res = await fs_read_multiple_files(["good.txt", r"..\..\.env"])
        self.assertIn("tool error: path denied", res)
        self.assertNotIn("Valid content", res)

        # Over 10 paths denies call
        too_many = [f"file_{i}.txt" for i in range(11)]
        res_limit = await fs_read_multiple_files(too_many)
        self.assertIn("maximum limit is 10", res_limit)

    # e) server ke tools me se jo allowlist me nahi (write_file jaise) -> registry me nahi, call par deny
    async def test_non_allowlisted_tools_not_registered_and_denied(self):
        self.assertIsNone(get_tool("write_file"))
        self.assertIsNone(get_tool("edit_file"))
        self.assertIsNone(get_tool("create_directory"))
        self.assertIsNone(get_tool("read_file"))
        self.assertIsNone(get_tool("list_allowed_directories"))

        # Policy decision rejects non-registered tools
        self.assertEqual(decide("write_file"), "deny")
        self.assertEqual(decide("edit_file"), "deny")

        # Direct async runner returns unrecognized error
        res = await run_tool_async("write_file", {"path": "test.txt", "content": "data"})
        self.assertIn("Error: Tool 'write_file' is not recognized", res)

    # f) bada file (>20000 chars) -> truncated; >5 MB full read -> deny
    async def test_large_file_and_5mb_limit(self):
        # Truncation for > 20000 chars
        large_file = self.ws_dir / "large.txt"
        large_file.write_text("a" * 25000, encoding="utf-8")

        res_trunc = await fs_read_text_file("large.txt")
        self.assertEqual(len(res_trunc), 20000 + len("[truncated]"))
        self.assertTrue(res_trunc.endswith("[truncated]"))

        # Full-file read over 5 MB denied
        huge_file = self.ws_dir / "huge.txt"
        # Write 5.1 MB
        with open(huge_file, "wb") as f:
            f.seek(5 * 1024 * 1024 + 1024)
            f.write(b"0")

        res_huge = await fs_read_text_file("huge.txt")
        self.assertIn("tool error: file size", res_huge)
        self.assertIn("exceeds 5 MB limit", res_huge)

        # Head/tail partial read is allowed even if file is large
        res_head = await fs_read_text_file("huge.txt", head=5)
        self.assertNotIn("exceeds 5 MB limit", res_head)

    # g) kill switch active -> koi fs tool nahi chale aur server process band
    async def test_kill_switch_blocks_fs_tools(self):
        # 1. Kill switch active from start: tool shouldn't run
        activate_kill_switch()
        try:
            res = await fs_read_text_file("sample.txt")
            self.assertIn("tool error: Kill switch is active", res)
        finally:
            clear_kill_switch()

        # 2. Server running, then kill switch activated -> server process stopped
        sample_file = self.ws_dir / "ks_sample.txt"
        sample_file.write_text("live content", encoding="utf-8")
        res_ok = await fs_read_text_file("ks_sample.txt")
        self.assertIn("live content", res_ok)

        activate_kill_switch()
        try:
            res_blocked = await fs_read_text_file("ks_sample.txt")
            self.assertIn("tool error: Kill switch is active", res_blocked)
            from tools import fs_tools
            if fs_tools._client is not None:
                self.assertFalse(
                    fs_tools._client.is_process_running(),
                    "Server process should be stopped when kill switch is active"
                )
        finally:
            clear_kill_switch()

    # h) server crash ya timeout (mock se simulate) -> orchestrator crash na ho, audit me error
    async def test_timeout_and_crash_handled_gracefully(self):
        from unittest.mock import patch
        from tools.mcp_client import FSMCPClient

        test_file = self.ws_dir / "dummy.txt"
        test_file.write_text("dummy", encoding="utf-8")

        # 1. Simulate timeout in tool call
        session_id_timeout = "test-fs-session-timeout"
        provider_timeout = MockProvider(
            tool_to_call="fs_read_text_file",
            args={"path": "dummy.txt"},
            final_text="Gracefully recovered after timeout",
        )
        with patch.object(FSMCPClient, "call_tool", side_effect=asyncio.TimeoutError("timeout after 30 seconds")):
            orch = Orchestrator(session_id=session_id_timeout, provider=provider_timeout)
            resp = await orch.run_turn("Read dummy.txt")
            self.assertIsNotNone(resp)
            self.assertEqual(resp, "Gracefully recovered after timeout")

            logs = read_latest_audit_logs(limit=5)
            tool_logs = [
                log for log in logs
                if log.get("session_id") == session_id_timeout and log.get("tool") == "fs_read_text_file"
            ]
            self.assertTrue(len(tool_logs) > 0)
            self.assertTrue(any("timeout" in str(log.get("result", "")) for log in tool_logs))

        # 2. Simulate server crash / unexpected exception
        session_id_crash = "test-fs-session-crash"
        provider_crash = MockProvider(
            tool_to_call="fs_read_text_file",
            args={"path": "dummy.txt"},
            final_text="Gracefully recovered after crash",
        )
        with patch.object(FSMCPClient, "call_tool", side_effect=RuntimeError("Server process crashed")):
            orch = Orchestrator(session_id=session_id_crash, provider=provider_crash)
            resp = await orch.run_turn("Read dummy.txt")
            self.assertIsNotNone(resp)
            self.assertEqual(resp, "Gracefully recovered after crash")

            logs = read_latest_audit_logs(limit=5)
            tool_logs = [
                log for log in logs
                if log.get("session_id") == session_id_crash and log.get("tool") == "fs_read_text_file"
            ]
            self.assertTrue(len(tool_logs) > 0)
            self.assertTrue(any("crashed" in str(log.get("result", "")) for log in tool_logs))

    # 3a) workspace ke andar mklink /J se junction banao jo workspace ke BAHAR ke ek temp folder ko point kare
    async def test_junction_outside_tree_search_list_and_read(self):
        outside_temp = tempfile.TemporaryDirectory()
        junction_link = self.ws_dir / "link_to_outside"
        try:
            outside_path = Path(os.path.realpath(outside_temp.name))
            secret_file = outside_path / "secret.txt"
            secret_file.write_text("OUTSIDE-SECRET", encoding="utf-8")

            if os.name != "nt":
                self.skipTest("Junction test only applicable on Windows")

            cmd = f'cmd /c mklink /J "{junction_link}" "{outside_path}"'
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if proc.returncode != 0:
                self.skipTest(f"OS refused to create junction: {proc.stderr}")

            # Phir fs_directory_tree(".") aur fs_search_files(".", "**/*")
            # aur fs_list_directory("link_to_outside") aur fs_read_text_file("link_to_outside/secret.txt") chalao.
            tree_res = await fs_directory_tree(".")
            search_res = await fs_search_files(".", "**/*")
            list_res = await fs_list_directory("link_to_outside")
            read_res = await fs_read_text_file("link_to_outside/secret.txt")

            # Result me "secret.txt" ya "OUTSIDE-SECRET" kahin nahi aana chahiye.
            for name, out in [("tree", tree_res), ("search", search_res), ("list", list_res), ("read", read_res)]:
                self.assertNotIn("OUTSIDE-SECRET", out, f"Secret content leaked in {name}: {out}")
                self.assertNotIn("secret.txt", out, f"Secret filename leaked in {name}: {out}")
        finally:
            if junction_link.exists():
                try:
                    os.rmdir(junction_link)
                except Exception:
                    pass
            outside_temp.cleanup()

    # 3c) tool error wali call audit me error field ke saath log ho (fix 1 ka test)
    async def test_tool_error_audit_field_logged(self):
        session_id = "test-fs-session-audit-error"
        provider = MockProvider(
            tool_to_call="fs_read_text_file",
            args={"path": r"..\..\.env"},
            final_text="Call concluded",
        )
        orch = Orchestrator(session_id=session_id, provider=provider)
        await orch.run_turn(r"Read ..\..\.env")

        logs = read_latest_audit_logs(limit=5)
        tool_logs = [
            log for log in logs
            if log.get("session_id") == session_id and log.get("tool") == "fs_read_text_file"
        ]
        self.assertTrue(len(tool_logs) > 0, "No audit log found for tool call")
        last_log = tool_logs[-1]
        self.assertIsNotNone(last_log.get("error"), f"Audit log error field is None: {last_log}")
        self.assertIn("tool error:", str(last_log.get("error")), f"Audit error did not start with 'tool error:': {last_log}")

    # 3d) head=-5 aur head=10**9 clamp/deny ho; 10 files ka total >5 MB ho to deny
    async def test_head_tail_clamping_and_total_multi_read_limit(self):
        test_file = self.ws_dir / "lines.txt"
        test_file.write_text("\n".join(f"line {i}" for i in range(20)), encoding="utf-8")

        # Non-integer head/tail
        res_invalid = await fs_read_text_file("lines.txt", head="invalid")
        self.assertEqual(res_invalid, "tool error: invalid head/tail")

        res_invalid_tail = await fs_read_text_file("lines.txt", tail="abc")
        self.assertEqual(res_invalid_tail, "tool error: invalid head/tail")

        # Negative head clamped to 1
        res_neg = await fs_read_text_file("lines.txt", head=-5)
        self.assertNotIn("invalid head/tail", res_neg)
        self.assertIn("line 0", res_neg)

        # Huge head clamped to 10000
        res_huge = await fs_read_text_file("lines.txt", head=10**9)
        self.assertNotIn("invalid head/tail", res_huge)
        self.assertIn("line 0", res_huge)

        # 10 files ka total > 5 MB ho to deny
        multi_paths = []
        for i in range(10):
            p = self.ws_dir / f"chunk_{i}.dat"
            with open(p, "wb") as f:
                f.write(b"x" * (600 * 1024))
            multi_paths.append(f"chunk_{i}.dat")

        res_multi = await fs_read_multiple_files(multi_paths)
        self.assertIn("tool error:", res_multi)
        self.assertIn("5 MB limit", res_multi)


if __name__ == "__main__":
    unittest.main()
