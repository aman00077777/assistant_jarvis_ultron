"""Automated verification suite for the 6 requested security and tool tests."""

import asyncio
import builtins
import json
import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# Ensure ASSISTANT_TEST=1 is active for the test suite
os.environ["ASSISTANT_TEST"] = "1"

from dotenv import load_dotenv

from core.orchestrator import Orchestrator
from core.paths import AUDIT_LOG_PATH
from policy.killswitch import activate_kill_switch, clear_kill_switch, is_kill_active
from policy.policy import decide
from tools.registry import get_tool


def read_latest_audit_logs(limit: int = 15) -> list[dict]:
    """Reads the last N lines from logs/audit.jsonl as parsed JSON objects."""
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


async def run_turn_with_retry(orchestrator: Orchestrator, prompt: str, max_retries: int = 3) -> str:
    """Executes orchestrator.run_turn with retries on transient 503/429 spikes."""
    for attempt in range(max_retries):
        resp = await orchestrator.run_turn(prompt)
        if ("429" in resp or "RESOURCE_EXHAUSTED" in resp) and attempt < max_retries - 1:
            wait = 18
            print(f"[Rate limit 429 encountered. Waiting {wait}s for quota reset before retry {attempt + 1}/{max_retries}...]")
            await asyncio.sleep(wait)
            continue
        if ("503" in resp or "UNAVAILABLE" in resp or "high demand" in resp) and attempt < max_retries - 1:
            wait = 4 * (attempt + 1)
            print(f"[Transient model spike 503. Waiting {wait}s before retry {attempt + 1}/{max_retries}...]")
            await asyncio.sleep(wait)
            continue
        return resp
    return resp


async def run_all_tests():
    load_dotenv()
    print("=" * 70)
    print("RUNNING VERIFICATION SUITE (ASSISTANT_TEST=1)")
    print("=" * 70)

    # -------------------------------------------------------------------------
    # TEST 0: Isolation check for test tools
    # Expectation: test_medium/high only available when ASSISTANT_TEST=1
    # -------------------------------------------------------------------------
    os.environ.pop("ASSISTANT_TEST", None)
    assert get_tool("test_medium") is None, "Isolation failed: test_medium found when ASSISTANT_TEST is unset"
    assert get_tool("test_high") is None, "Isolation failed: test_high found when ASSISTANT_TEST is unset"

    os.environ["ASSISTANT_TEST"] = "1"
    assert get_tool("test_medium") is not None, "Failed: test_medium not found when ASSISTANT_TEST=1"
    assert get_tool("test_high") is not None, "Failed: test_high not found when ASSISTANT_TEST=1"
    print("TEST 0 PASSED: Test tools isolated behind ASSISTANT_TEST=1.")

    # Clean any stale kill switch before starting
    if is_kill_active():
        clear_kill_switch()

    # -------------------------------------------------------------------------
    # TEST 1: Low Risk Tool ("Abhi time kya hai?")
    # Expectation: get_current_time runs automatically, audit log shows "allow"
    # -------------------------------------------------------------------------
    print("\n--- TEST 1: 'Abhi time kya hai?' (Low Risk) ---")
    orchestrator_1 = Orchestrator(session_id="test_session_1")
    resp_1 = await run_turn_with_retry(orchestrator_1, "Abhi time kya hai?")
    print(f"Assistant Response: {resp_1}")

    recent_logs = read_latest_audit_logs(10)
    test1_log = next(
        (log for log in reversed(recent_logs) if log.get("session_id") == "test_session_1" and log.get("tool") == "get_current_time"),
        None,
    )
    assert test1_log is not None, f"Test 1 Failed: get_current_time not found in audit log. Response: {resp_1}"
    assert test1_log.get("decision") == "allow", f"Test 1 Failed: expected 'allow', got {test1_log.get('decision')}"
    print(f"TEST 1 PASSED: get_current_time allowed without prompt. Log decision: {test1_log.get('decision')}")

    # -------------------------------------------------------------------------
    # TEST 2: Medium Risk Tool ("test_medium tool chalao.")
    # Expectation: console notify shown, runs, audit log shows "allow_notify"
    # -------------------------------------------------------------------------
    print("\n--- TEST 2: 'test_medium tool chalao.' (Medium Risk) ---")
    orchestrator_2 = Orchestrator(session_id="test_session_2")
    resp_2 = await run_turn_with_retry(orchestrator_2, "test_medium tool chalao.")
    print(f"Assistant Response: {resp_2}")

    recent_logs = read_latest_audit_logs(10)
    test2_log = next(
        (log for log in reversed(recent_logs) if log.get("session_id") == "test_session_2" and log.get("tool") == "test_medium"),
        None,
    )
    assert test2_log is not None, f"Test 2 Failed: test_medium not found in audit log. Response: {resp_2}"
    assert test2_log.get("decision") == "allow_notify", f"Test 2 Failed: expected 'allow_notify', got {test2_log.get('decision')}"
    print(f"TEST 2 PASSED: test_medium executed with notify. Log decision: {test2_log.get('decision')}")

    # -------------------------------------------------------------------------
    # TEST 3a: High Risk Tool with 'n' ("test_high tool chalao.")
    # Expectation: y/n prompt, input 'n', tool denied, audit log shows "deny"
    # -------------------------------------------------------------------------
    print("\n--- TEST 3a: 'test_high tool chalao.' with 'n' (High Risk Denial) ---")
    orchestrator_3a = Orchestrator(session_id="test_session_3a")
    orig_input = builtins.input
    try:
        builtins.input = lambda prompt="": "n"
        resp_3a = await run_turn_with_retry(orchestrator_3a, "test_high tool chalao.")
    finally:
        builtins.input = orig_input
    print(f"Assistant Response: {resp_3a}")

    recent_logs = read_latest_audit_logs(10)
    test3a_log = next(
        (log for log in reversed(recent_logs) if log.get("session_id") == "test_session_3a" and log.get("tool") == "test_high"),
        None,
    )
    assert test3a_log is not None, f"Test 3a Failed: test_high not found in audit log. Response: {resp_3a}"
    assert test3a_log.get("decision") == "user_denied", f"Test 3a Failed: expected 'user_denied', got {test3a_log.get('decision')}"
    print(f"TEST 3a PASSED: test_high denied on 'n'. Log decision: {test3a_log.get('decision')}")

    # -------------------------------------------------------------------------
    # TEST 3b: High Risk Tool with 'y' ("test_high tool chalao.")
    # Expectation: y/n prompt, input 'y', tool allowed, executes
    # -------------------------------------------------------------------------
    print("\n--- TEST 3b: 'test_high tool chalao.' with 'y' (High Risk Approval) ---")
    orchestrator_3b = Orchestrator(session_id="test_session_3b")
    try:
        builtins.input = lambda prompt="": "y"
        resp_3b = await run_turn_with_retry(orchestrator_3b, "test_high tool chalao.")
    finally:
        builtins.input = orig_input
    print(f"Assistant Response: {resp_3b}")

    recent_logs = read_latest_audit_logs(10)
    test3b_log = next(
        (log for log in reversed(recent_logs) if log.get("session_id") == "test_session_3b" and log.get("tool") == "test_high" and log.get("decision") != "deny"),
        None,
    )
    assert test3b_log is not None, f"Test 3b Failed: confirmed test_high not found in audit log. Response: {resp_3b}"
    print(f"TEST 3b PASSED: test_high executed on 'y'. Log decision: {test3b_log.get('decision')}")

    # Verify requested event logged before tool execution (Requirement 3)
    requested_log = next(
        (log for log in reversed(recent_logs) if log.get("session_id") == "test_session_3b" and log.get("tool") == "test_high" and log.get("decision") == "requested"),
        None,
    )
    assert requested_log is not None, "Requested audit event was not logged before tool execution"
    print("TEST 3b-REQ PASSED: Tool requested event logged prior to execution.")

    # -------------------------------------------------------------------------
    # TEST 4a: Kill Switch Active
    # Expectation: data/KILL exists, tool does NOT run, session ends
    # -------------------------------------------------------------------------
    print("\n--- TEST 4a: Kill Switch Active (Tool Execution Blocked) ---")
    activate_kill_switch()
    orchestrator_4a = Orchestrator(session_id="test_session_4a")
    resp_4a = await orchestrator_4a.run_turn("Abhi time kya hai?")
    print(f"Assistant Response: {resp_4a}")

    recent_logs = read_latest_audit_logs(10)
    test4a_log = next(
        (log for log in reversed(recent_logs) if log.get("session_id") == "test_session_4a" and log.get("decision") == "killed"),
        None,
    )
    assert test4a_log is not None, "Test 4a Failed: killed event not found in audit log"
    assert "[Session terminated by kill switch]" in resp_4a, f"Test 4a Failed: unexpected response {resp_4a}"
    print(f"TEST 4a PASSED: Tool blocked by kill switch. Log decision: {test4a_log.get('decision')}")

    # -------------------------------------------------------------------------
    # TEST 4b: Kill Switch Cleared
    # Expectation: data/KILL removed, tools run normally again
    # -------------------------------------------------------------------------
    print("\n--- TEST 4b: Kill Switch Cleared (Tool Execution Restored) ---")
    clear_kill_switch()
    orchestrator_4b = Orchestrator(session_id="test_session_4b")
    resp_4b = await run_turn_with_retry(orchestrator_4b, "Abhi time kya hai?")
    print(f"Assistant Response: {resp_4b}")

    recent_logs = read_latest_audit_logs(10)
    test4b_log = next(
        (log for log in reversed(recent_logs) if log.get("session_id") == "test_session_4b" and log.get("tool") == "get_current_time" and log.get("decision") == "allow"),
        None,
    )
    assert test4b_log is not None, f"Test 4b Failed: get_current_time did not resume normally for session 4b. Response: {resp_4b}"
    print(f"TEST 4b PASSED: Normal tool execution resumed after clearing kill switch. Log decision: {test4b_log.get('decision')}")

    # -------------------------------------------------------------------------
    # TEST 5: Secret Leak Check in logs/audit.jsonl
    # Expectation: No line contains 'AIza'
    # -------------------------------------------------------------------------
    print("\n--- TEST 5: Secret Leak Check (Pattern: AIza) ---")
    log_file = str(AUDIT_LOG_PATH)
    leaks = []
    if os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f, 1):
                if "AIza" in line:
                    leaks.append((idx, line))

    assert len(leaks) == 0, f"Test 5 Failed: Secret leak detected on lines: {[idx for idx, _ in leaks]}"
    print("TEST 5 PASSED: logs/audit.jsonl contains ZERO occurrences of 'AIza'.")

    # -------------------------------------------------------------------------
    # TEST 6a: Unknown Tool Policy Deny & Caller Risk Ignore (Requirement 2 & 8a)
    # -------------------------------------------------------------------------
    print("\n--- TEST 6a: Unknown Tool Deny & Caller Risk Ignored ---")
    assert decide("non_existent_tool_xyz") == "deny", "Unknown tool was not denied"
    # Even if caller passes risk="low", unknown tool is denied
    assert decide("non_existent_tool_xyz", risk="low") == "deny", "Unknown tool with low risk was not denied"
    # Even if caller passes risk="high", get_current_time contract risk (low) is used
    assert decide("get_current_time", risk="high") == "allow", "Caller risk override was not ignored"
    print("TEST 6a PASSED: Unknown tool denied; contract risk enforced over caller risk.")

    # -------------------------------------------------------------------------
    # TEST 6b: Tool Exception Handling (Requirement 3 & 8b)
    # -------------------------------------------------------------------------
    print("\n--- TEST 6b: Tool Exception Handling (No Crash, Error in Audit) ---")
    orchestrator_6b = Orchestrator(session_id="test_session_6b")
    resp_6b = await run_turn_with_retry(orchestrator_6b, "test_faulty tool chalao.")
    print(f"Assistant Response: {resp_6b}")

    recent_logs = read_latest_audit_logs(10)
    test6b_log = next(
        (log for log in reversed(recent_logs) if log.get("session_id") == "test_session_6b" and log.get("tool") == "test_faulty"),
        None,
    )
    assert test6b_log is not None, "test_faulty execution not found in audit log"
    assert test6b_log.get("error") is not None, "Error field missing in audit log for failing tool"
    assert "Intentional tool failure" in str(test6b_log.get("error")), f"Unexpected error log: {test6b_log.get('error')}"
    print("TEST 6b PASSED: Tool exception handled gracefully without crash; error logged to audit.")

    # -------------------------------------------------------------------------
    # TEST 6c: Session Taint (Requirement 8c)
    # -------------------------------------------------------------------------
    print("\n--- TEST 6c: Session Taint with test_taint (returns_untrusted=True) ---")
    orchestrator_6c = Orchestrator(session_id="test_session_6c")
    assert orchestrator_6c.untrusted_seen is False, "New session should not be tainted"
    assert decide("test_medium", untrusted_seen=orchestrator_6c.untrusted_seen) == "allow_notify"

    resp_6c = await run_turn_with_retry(orchestrator_6c, "test_taint tool chalao.")
    print(f"Assistant Response: {resp_6c}")
    assert orchestrator_6c.untrusted_seen is True, "Session was not tainted after executing returns_untrusted tool"
    assert decide("test_medium", untrusted_seen=orchestrator_6c.untrusted_seen) == "confirm", (
        "Medium-risk tool did not escalate to 'confirm' after taint"
    )
    print("TEST 6c PASSED: Session tainted; subsequent medium-risk tool requires confirmation.")

    # -------------------------------------------------------------------------
    # TEST 6d: Kill Switch Anchored Outside Project CWD (Requirement 1 & 8d)
    # -------------------------------------------------------------------------
    print("\n--- TEST 6d: Kill Switch Works Outside Project CWD ---")
    import tempfile
    orig_cwd = os.getcwd()
    temp_dir = tempfile.gettempdir()
    try:
        os.chdir(temp_dir)
        # Should not be active initially
        assert not is_kill_active(), "Kill switch should not be active initially"
        activate_kill_switch()
        assert is_kill_active(), "Kill switch was not detected when cwd changed to temp_dir"
        clear_kill_switch()
        assert not is_kill_active(), "Kill switch was not cleared when cwd was temp_dir"
    finally:
        os.chdir(orig_cwd)
    print("TEST 6d PASSED: Kill switch reliably anchored to project root across working directories.")

    # -------------------------------------------------------------------------
    # TEST 6e: Redaction of sk-, ghp-, Bearer, and sensitive env vars (Requirement 5)
    # -------------------------------------------------------------------------
    print("\n--- TEST 6e: Advanced Redaction Check ---")
    from audit.audit import redact_string
    os.environ["SECRET_PASS_KEY"] = "supersecretpass12345"
    sample_text = (
        "Authorization: Bearer my_jwt_token_abcdef123. "
        "OpenAI: sk-9876543210abcdefghij123456. "
        "GitHub: ghp_1234567890abcdefghijklmnopqrstuv. "
        "Secret: supersecretpass12345."
    )
    redacted = redact_string(sample_text)
    assert "Bearer [REDACTED]" in redacted, f"Bearer token not redacted: {redacted}"
    assert "sk-9876543210abcdefghij123456" not in redacted, f"sk- token not redacted: {redacted}"
    assert "ghp_1234567890abcdefghijklmnopqrstuv" not in redacted, f"ghp- token not redacted: {redacted}"
    assert "supersecretpass12345" not in redacted, f"Sensitive env var value not redacted: {redacted}"
    print("TEST 6e PASSED: Generic tokens and sensitive environment variable values redacted.")

    # -------------------------------------------------------------------------
    # TEST 6f: confirm_execution args formatting and control char removal (Requirement 4)
    # -------------------------------------------------------------------------
    print("\n--- TEST 6f: confirm_execution args formatting ---")
    from policy.policy import _format_args_for_display
    dirty_args = {"cmd": "echo test\nrm -rf /\x00null\x1b[31mcolor", "buffer": "a" * 400}
    clean_display = _format_args_for_display(dirty_args)
    assert "\n" not in clean_display, "Newlines found in formatted args"
    assert "\x00" not in clean_display, "Null byte found in formatted args"
    assert "\x1b" not in clean_display, "Escape sequence found in formatted args"
    assert len(clean_display) <= 320, f"Display args not truncated: {len(clean_display)}"
    print("TEST 6f PASSED: confirm_execution safely formats and truncates args.")

    # -------------------------------------------------------------------------
    # TEST 6g: Orchestrator session start/end with uuid4 (Requirement 6)
    # -------------------------------------------------------------------------
    print("\n--- TEST 6g: Session Lifecycle with uuid4 ---")
    orch_lifecycle = Orchestrator()
    assert orch_lifecycle.session_id is not None
    assert len(orch_lifecycle.session_id) >= 32, "session_id is not a uuid4 hex string"
    orch_lifecycle.end_session("Test session done")
    recent_logs = read_latest_audit_logs(10)
    sess_start_log = next((l for l in recent_logs if l.get("session_id") == orch_lifecycle.session_id and l.get("decision") == "session_start"), None)
    sess_end_log = next((l for l in recent_logs if l.get("session_id") == orch_lifecycle.session_id and l.get("decision") == "session_end"), None)
    assert sess_start_log is not None, "session_start event not found in audit log"
    assert sess_end_log is not None, "session_end event not found in audit log"
    print("TEST 6g PASSED: Session start and end events logged with uuid4 session_id.")

    # -------------------------------------------------------------------------
    # TEST 6h: High-risk tool blocked if audit write fails (Requirement 3)
    # -------------------------------------------------------------------------
    print("\n--- TEST 6h: High-Risk Tool Blocked on Audit Failure ---")
    orch_fail_write = Orchestrator(session_id="test_session_fail_write")
    import audit.audit as audit_module
    orig_log_event = audit_module.log_event
    try:
        # Simulate audit log write failure
        audit_module.log_event = lambda *args, **kwargs: False
        orig_input = builtins.input
        try:
            builtins.input = lambda prompt="": "y"
            resp_fail = await run_turn_with_retry(orch_fail_write, "test_high tool chalao.")
        finally:
            builtins.input = orig_input
    finally:
        audit_module.log_event = orig_log_event

    assert "Audit log write failed" in resp_fail or "audit write failed" in resp_fail.lower(), (
        f"High risk tool was not blocked on audit write failure: {resp_fail}"
    )
    print("TEST 6h PASSED: High-risk tool blocked when audit logging fails.")

    print("\n" + "=" * 70)
    print("ALL VERIFICATION SUITE TESTS COMPLETED SUCCESSFULLY!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(run_all_tests())
