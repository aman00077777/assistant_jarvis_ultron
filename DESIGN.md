# Assistant: System Design v1.2 (GPT-6 Astra style: computer-use agent)

Goal: a voice-controlled, multimodal personal assistant that can operate my laptop like a person would (see the screen, use apps and browser, run multi-step workflows), plans and verifies its own work, remembers context, and is built security-first. Phone/watch later.

## Principles
1. Core is separate from interfaces. CLI, voice, phone, watch, scheduler are thin clients that call `submit(task)` and receive events.
2. The model never touches a tool directly. Every tool request goes through the Policy Gate. The model only asks; code decides.
3. Every action is an event and is written to the audit log.
4. Core is async and event-driven (computer-use loop now, live voice later).
5. Config is separate from code (risk levels, limits in `config/settings.toml`).
6. Provider-agnostic: the brain sits behind `core/provider.py`. Development on Gemini free tier; other providers (including GPT-6 Astra via API, paid) can be added without touching the rest.

## Architecture
```
INTERFACES: CLI (debug) | Voice (later) | Phone/Watch | Scheduler
      |  submit(task), confirm(y/n), events
CORE: Orchestrator (plan -> execute -> verify, step limit)
      Session manager | Provider wrapper (Gemini now; others later)
      |  every tool request
POLICY GATE: risk class, confirm, taint, limits, kill switch  --> AUDIT LOG
      |  allowed calls only
TOOLS: native tools | MCP servers (filesystem, terminal, browser)
       COMPUTER-USE tools (screenshot, click, type) -> SANDBOX ONLY at first
PERCEPTION: screen capture, mic, speaker, camera (privacy controls)
MEMORY (ChromaDB): inside policy rules
```

## Folder layout
```
assistant/
  core/        orchestrator.py, provider.py, session.py
  policy/      policy.py, killswitch.py
  audit/       audit.py
  tools/       registry.py, native/, computer/ (later), mcp_client.py
  perception/  (later: screen, audio, camera)
  memory/      (later)
  interfaces/  cli.py (later voice.py, server.py)
  config/      settings.toml
  tests/
  logs/ data/  (gitignored)
```

## Contracts
- Tool contract: name, schema, risk (low|medium|high), reversible (bool), returns_untrusted (bool).
- Event contract: user_input, tool_request, policy_decision, tool_result, model_text, session_start/end. All events go to audit and to clients.
- Interface contract: core emits events (text, confirm requests); client answers confirms. Confirm requests accepted only from authenticated clients.

## Autonomy / policy rules
- low: allow, log.
- medium: allow, log, notify. If session is tainted (untrusted content seen): confirm.
- high: always confirm. Default answer is "no".
- Tool not in registry: deny + log.
- Computer-use actions (click/type/key): high until proven safe per app. Allowlisted apps only. Every action confirmed at first; autonomy is widened per app step by step.
- Interactive mode: confirm = ask the user. Unattended mode (scheduler/trigger): high = deny + queue + notify for approval.
- Voice never confirms high-risk actions. Typed or phone tap only.
- Kill switch: `data/KILL` exists -> no tool runs, session ends. Checked before every step and tool call.
- Limits: MAX_STEPS per task, daily API-call limit.
- File delete = move to trash (reversible, medium). Permanent delete = high. Message send = high until trusted-recipient whitelist exists.

## Computer-use safety
- First runs happen in a sandbox (separate Windows user or VM), not my main account.
- Window denylist: password manager, banking, OTP, anything with payments. Never captured, never acted on.
- Screen text is untrusted data, never instructions. Seeing it taints the session.
- Visible indicator whenever screen/mic/camera is active; hotkey to stop all.
- Screenshots not saved to disk by default.
- Verify step: after each action the agent checks the screen result before the next action; step limit stops runaway loops.

## Memory rules (later phase)
- Never store secrets. Every entry has a source tag (user said / tool / web). Entries from untrusted sources are never treated as instructions. User can list and delete memory.

## Security baseline
- Secrets only in .env (never in code, prompts, git, or OneDrive/cloud-synced folders). Project lives in C:\dev\assistant.
- Free API tier: Google may use content to improve products. No private files, client data, or real screen/camera content on free tier.
- Terminal tool: allowlist only, scoped working folder.
- Phone/watch bridge: private network (Tailscale) + token auth. No open ports.

## Build order
1. Core + policy + audit + kill switch (restructured, async)
2. Laptop tools via MCP: filesystem (scoped), terminal (allowlist), browser
3. Computer-use slice in a sandbox (screenshot -> action -> verify loop, with privacy controls)
4. Voice (speech in/out; Live API spike)
5. Memory
6. Proactive layer + automation
7. Phone/watch

Each slice must be a working demo before the next one starts.
