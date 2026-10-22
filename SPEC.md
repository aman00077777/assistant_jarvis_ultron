# SPEC: Phase 1, Step 4 - Scoped filesystem tools via MCP

Read DESIGN.md first. This spec must not change policy/, audit/, killswitch or core/orchestrator.py behaviour. New code goes in tools/, config/, tests/.

## Goal
The assistant can read, search and write files, but only inside one workspace folder, and every file tool call goes through the existing Policy Gate and Audit log.

## Workspace
- Folder: C:\dev\assistant-workspace (configurable in config/settings.toml as `workspace_dir`).
- At startup, resolve it with realpath. REFUSE TO START the filesystem tools if the workspace is inside the project root, equals it, or is a parent of it. (Otherwise the agent could edit its own policy, logs or kill switch.)
- Create the folder if missing.

## Architecture
- tools/mcp_client.py: async MCP client that starts the official filesystem MCP server (Node, via npx) restricted to the workspace folder, lists its tools at runtime, and exposes them as tool contracts in tools/registry.py.
- Do not trust tool names from memory: take them from the server's list_tools at runtime.
- tools/fs_policy_map.py: explicit allowlist mapping MCP tool name -> contract. Any MCP tool NOT in this map is not registered (so the policy denies it by default).
- Server process is started per session and stopped on session end and on kill switch.

## Risk mapping (contract fields: risk, reversible, returns_untrusted)
- read file, read multiple files, list directory, directory tree, search files, file info: risk=low, returns_untrusted=True.
- create directory, write new file, edit file: risk=medium, reversible=False unless a backup is kept.
- move/rename: risk=high.
- delete (if the server offers it): risk=high. If unsure about a tool, leave it out of the map.
- The existing taint rule applies: after any read tool runs, medium tools need confirmation.

## Defense in depth (our own checks before calling the server)
For every path argument:
1. Resolve with realpath (follow symlinks/junctions). Must be inside the workspace realpath. Otherwise deny and log.
2. Reject `..` escapes, absolute paths outside the workspace, UNC paths (\\server\share), drive-letter changes, and NTFS alternate data streams (a ":" after the drive letter).
3. Case-insensitive comparison on Windows.
4. Reject paths that resolve into the project root, its .git, .env, data/ or logs/ even if somehow reachable.

## Limits
- Tool result returned to the model: truncate to 20,000 characters with a "[truncated]" marker.
- Write size limit: 1 MB per call.
- Per-tool-call timeout: 30 seconds; on timeout return "tool error: timeout" and log it.

## Audit
Every call is already logged by the orchestrator (requested -> decision -> result). Make sure path arguments appear in the log (truncated, redacted).

## Acceptance tests (tests/test_fs_tools.py, mock provider by default; real model only with --live)
1. Workspace inside project root -> fs tools refuse to start (clear error).
2. Read a file inside the workspace -> works, audit shows allow, session becomes tainted.
3. `..\..\.env` style traversal -> denied, logged, nothing read.
4. Absolute path outside workspace (e.g. C:\Windows\win.ini) -> denied.
5. Symlink/junction inside workspace pointing outside -> denied (create the junction in the test, skip with a clear message if the OS refuses).
6. UNC path and "file.txt:stream" path -> denied.
7. Unknown MCP tool name from the server -> not registered; a call attempt is denied.
8. write file in a clean session -> allow_notify; after a read in the same session -> confirm required.
9. Large file read -> result truncated to 20,000 chars. Write over 1 MB -> rejected.
10. Kill switch active -> no fs tool runs and the server process is stopped.
11. Server crash or timeout -> orchestrator does not crash; audit contains the error.
12. Existing tests in tests/test_verification.py still pass.

## Out of scope
Terminal tool, browser tool, computer use, memory, voice. No changes to policy rules.

## Done means
All acceptance tests pass, `git status` shows no .env or logs, and I have reviewed the diff of tools/ before merge.
