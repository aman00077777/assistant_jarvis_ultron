"""Orchestrator: manages agentic loop with Observe -> Act -> Verify structure."""

import uuid
from typing import Any
from google.genai import types

import audit


def log_event(*args, **kwargs) -> bool:
    return audit.log_event(*args, **kwargs)

from config import get_max_steps
from core.provider import BaseLLMProvider, GeminiProvider
from policy import confirm_execution, decide, is_kill_active
from tools import get_tools, run_tool, run_tool_async, TOOL_REGISTRY
from tools.registry import get_tool


class Orchestrator:
    """Core orchestrator executing agentic loop."""

    def __init__(
        self,
        provider: BaseLLMProvider | None = None,
        session_id: str | None = None,
    ):
        self.provider = provider or GeminiProvider()
        self.session_id = session_id or uuid.uuid4().hex
        self.messages: list[types.Content] = []
        self.max_steps = get_max_steps()
        self.untrusted_seen = False
        self._session_started = False
        self._session_ended = False

        # Log session start
        self.start_session()

    def start_session(self) -> None:
        """Logs session_start event if not already started."""
        if not self._session_started:
            self._session_started = True
            log_event(
                session_id=self.session_id,
                tool="__session__",
                decision="session_start",
                result="Session started",
            )

    def end_session(self, reason: str = "Session ended") -> None:
        """Logs session_end event if not already ended."""
        if not self._session_ended:
            self._session_ended = True
            log_event(
                session_id=self.session_id,
                tool="__session__",
                decision="session_end",
                result=reason,
            )

    async def run_turn(self, user_input: str) -> str:
        """
        Executes a single user turn in the agentic loop.
        Structure:
          1. OBSERVE (hook for perception)
          2. ACT (LLM reasoning, policy gate, tool execution)
          3. VERIFY (hook for verification)
        """
        if not self._session_started:
            self.start_session()

        # Append user message to history
        self.messages.append(
            types.Content(
                role="user",
                parts=[types.Part.from_text(text=user_input)],
            )
        )

        step = 0
        tools = get_tools()

        while step < self.max_steps:
            # -----------------------------------------------------------------
            # 1. OBSERVE (placeholder: future screen capture / perception hook)
            # -----------------------------------------------------------------
            # TODO (observe): Capture active screen, window info, or sensor inputs

            # -----------------------------------------------------------------
            # 2. ACT: Kill switch check, LLM generation, policy gate, tools
            # -----------------------------------------------------------------
            if is_kill_active():
                print("\n[KILL SWITCH DETECTED] 'data/KILL' file present at loop step start. Stopping.")
                log_event(
                    session_id=self.session_id,
                    tool="__kill_switch__",
                    decision="killed",
                    error="data/KILL detected at loop step start",
                )
                self.end_session("Terminated by kill switch")
                return "[Session terminated by kill switch]"

            # Query the provider with current history and tool declarations
            try:
                response = await self.provider.generate(
                    messages=self.messages,
                    tools=tools,
                )
            except Exception as e:
                err_msg = f"Provider error: {e}"
                print(f"\n{err_msg}\n")
                log_event(
                    session_id=self.session_id,
                    tool="__provider__",
                    decision="error",
                    error=err_msg,
                )
                return err_msg

            # If model returned text response and no tool calls, turn is complete
            if not response.function_calls:
                if response.candidates and response.candidates[0].content:
                    self.messages.append(response.candidates[0].content)

                return response.text or ""

            # Model requested function call(s) - record model turn in history
            if response.candidates and response.candidates[0].content:
                self.messages.append(response.candidates[0].content)

            step += 1
            tool_response_parts: list[types.Part] = []

            for call in response.function_calls:
                tool_name = call.name
                args = call.args or {}
                tool_contract = get_tool(tool_name) or TOOL_REGISTRY.get(tool_name)
                risk = tool_contract.risk if tool_contract else None

                # Pre-tool execution kill switch check
                if is_kill_active():
                    print(f"\n[KILL SWITCH DETECTED] 'data/KILL' file present before executing '{tool_name}'.")
                    log_event(
                        session_id=self.session_id,
                        tool=tool_name,
                        args=args,
                        risk=risk,
                        decision="killed",
                        error=f"data/KILL detected before executing tool '{tool_name}'",
                    )
                    self.end_session("Terminated by kill switch")
                    return "[Session terminated by kill switch]"

                # Policy gate evaluation (caller-provided risk is ignored inside decide)
                decision = decide(tool_name, args, risk, self.untrusted_seen)

                # Ask for user confirmation if required
                if decision == "confirm":
                    if not confirm_execution(tool_name, args):
                        decision = "user_denied"

                # Re-check kill switch after confirmation and before tool execution
                if is_kill_active():
                    print(f"\n[KILL SWITCH DETECTED] 'data/KILL' file present after confirmation for '{tool_name}'.")
                    log_event(
                        session_id=self.session_id,
                        tool=tool_name,
                        args=args,
                        risk=risk,
                        decision="killed",
                        error=f"data/KILL detected after confirmation before executing tool '{tool_name}'",
                    )
                    self.end_session("Terminated by kill switch")
                    return "[Session terminated by kill switch]"

                # Execute or Deny
                if decision in ("allow", "allow_notify", "confirm"):
                    if decision == "allow_notify":
                        print(f"[policy notify] Executing tool '{tool_name}' (risk={risk})...")

                    # Log requested event before executing tool
                    audit_ok = log_event(
                        session_id=self.session_id,
                        tool=tool_name,
                        args=args,
                        risk=risk,
                        decision="requested",
                    )

                    # For high-risk tool, if audit write fails, do not execute tool
                    if risk == "high" and not audit_ok:
                        print(f"[policy deny] Audit write failed for high-risk tool '{tool_name}'. Execution blocked.")
                        tool_result = "tool error: Audit log write failed for high-risk tool"
                        tool_error = "Audit log write failed for high-risk tool"
                    else:
                        # Orchestrator me run_tool try/except me
                        try:
                            tool_result = await run_tool_async(tool_name, args)
                            tool_error = None
                        except Exception as e:
                            tool_result = f"tool error: {e}"
                            tool_error = str(e)

                        print(f"[tool] {tool_name}({args}) -> {tool_result}")

                        # If tool returns untrusted data, taint the session
                        if tool_contract and tool_contract.returns_untrusted:
                            self.untrusted_seen = True

                    # Log decision/result event in audit
                    log_event(
                        session_id=self.session_id,
                        tool=tool_name,
                        args=args,
                        risk=risk,
                        decision=decision,
                        result=tool_result,
                        error=tool_error,
                    )
                elif decision == "user_denied":
                    print(f"[policy deny] Confirmation for tool '{tool_name}' rejected by user.")
                    tool_result = "denied by policy"
                    log_event(
                        session_id=self.session_id,
                        tool=tool_name,
                        args=args,
                        risk=risk,
                        decision="user_denied",
                        result=tool_result,
                        error="Confirmation rejected by user",
                    )
                else:  # decision == "deny"
                    print(f"[policy deny] Tool '{tool_name}' execution was denied by policy.")
                    tool_result = "denied by policy"
                    log_event(
                        session_id=self.session_id,
                        tool=tool_name,
                        args=args,
                        risk=risk,
                        decision="deny",
                        result=tool_result,
                        error="Denied by policy",
                    )

                tool_response_parts.append(
                    types.Part.from_function_response(
                        name=tool_name,
                        response={"result": tool_result},
                    )
                )

            # Append tool responses as user/tool turn in history
            self.messages.append(
                types.Content(
                    role="user",
                    parts=tool_response_parts,
                )
            )

            # -----------------------------------------------------------------
            # 3. VERIFY (placeholder: future verification hook)
            # -----------------------------------------------------------------
            # TODO (verify): Verify tool outcome against expected screen/system state

        # When MAX_STEPS is reached
        notice = f"\n[Notice] MAX_STEPS ({self.max_steps}) limit reached. Stopping tool loop."
        print(notice)
        return notice
