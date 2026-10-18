"""CLI interface for assistant: terminal input loop."""

import asyncio
import uuid
from dotenv import load_dotenv

from audit import log_event
from core.orchestrator import Orchestrator
from policy import is_kill_active


async def main():
    # Load environment variables without reading or modifying .env directly
    load_dotenv()

    session_id = uuid.uuid4().hex
    try:
        orchestrator = Orchestrator(session_id=session_id)
    except Exception as e:
        print(f"Initialization error: {e}")
        log_event(
            session_id=session_id,
            tool="__session__",
            decision="session_end",
            result=f"Initialization failed: {e}",
        )
        return

    def end_session(reason: str = "Session ended"):
        orchestrator.end_session(reason)

    print("Agent session started (type 'exit' or 'quit' to end).\n")

    try:
        while True:
            # Check kill switch before prompting user
            if is_kill_active():
                print("\n[KILL SWITCH DETECTED] 'data/KILL' file exists. Terminating session.")
                log_event(
                    session_id=session_id,
                    tool="__kill_switch__",
                    decision="killed",
                    error="data/KILL detected before user input",
                )
                end_session("Terminated by kill switch")
                break

            try:
                user_input = input("User: ").strip()
            except EOFError:
                print("\nSession ended.")
                end_session("EOF received")
                break

            if not user_input:
                continue

            if user_input.lower() in ("exit", "quit"):
                end_session("User requested exit")
                print("Session ended.")
                break

            # Execute turn through orchestrator
            response_text = await orchestrator.run_turn(user_input)

            if response_text:
                if response_text.startswith("["):
                    print(f"\n{response_text}\n")
                else:
                    print(f"\nAssistant: {response_text}\n")

            if response_text == "[Session terminated by kill switch]":
                end_session("Terminated by kill switch")
                break

    except KeyboardInterrupt:
        print("\nSession interrupted by user (Ctrl+C).")
        end_session("Interrupted by Ctrl+C")
    finally:
        end_session("Session completed")


if __name__ == "__main__":
    asyncio.run(main())
