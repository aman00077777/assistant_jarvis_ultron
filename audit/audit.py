"""Audit logging system with redaction for agent actions."""

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.paths import AUDIT_LOG_PATH

AIZA_PATTERN = re.compile(r"AIza[0-9A-Za-z_-]+")
SK_PATTERN = re.compile(r"sk-[0-9A-Za-z_-]+")
GHP_PATTERN = re.compile(r"ghp_[0-9A-Za-z_-]+")
BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-~+/]+=*")

SENSITIVE_ENV_KEYWORDS = ("KEY", "TOKEN", "SECRET", "PASSWORD")


def _get_env_secrets() -> list[str]:
    """Finds values of environment variables whose names contain KEY, TOKEN, SECRET, or PASSWORD (len > 5)."""
    secrets: list[str] = []
    for k, v in os.environ.items():
        if any(kw in k.upper() for kw in SENSITIVE_ENV_KEYWORDS):
            val = str(v).strip()
            if len(val) > 5:
                secrets.append(val)
    # Sort descending by length so longer patterns match first
    return sorted(set(secrets), key=len, reverse=True)


def redact_string(val: str) -> str:
    """
    Redacts:
    - AIza patterns
    - sk-... patterns
    - ghp_... patterns
    - 'Bearer <token>' patterns
    - Values of env vars whose names contain KEY, TOKEN, SECRET, or PASSWORD (len > 5)
    """
    if not isinstance(val, str):
        return val

    sanitized = val

    # Redact Bearer tokens
    sanitized = BEARER_PATTERN.sub("Bearer [REDACTED]", sanitized)

    # Redact AIza patterns
    sanitized = AIZA_PATTERN.sub("[REDACTED]", sanitized)

    # Redact sk-... patterns
    sanitized = SK_PATTERN.sub("[REDACTED]", sanitized)

    # Redact ghp_... patterns
    sanitized = GHP_PATTERN.sub("[REDACTED]", sanitized)

    # Redact sensitive env var values
    for secret in _get_env_secrets():
        sanitized = sanitized.replace(secret, "[REDACTED]")

    return sanitized


def sanitize_data(data: Any) -> Any:
    """Recursively redacts strings in structures (dicts, lists, primitives)."""
    if isinstance(data, str):
        return redact_string(data)
    elif isinstance(data, dict):
        return {k: sanitize_data(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_data(v) for v in data]
    return data


def log_event(
    session_id: str,
    tool: str | None = None,
    args: Any = None,
    risk: str | None = None,
    decision: str | None = None,
    result: Any = None,
    error: str | None = None,
    log_file: str | Path = AUDIT_LOG_PATH,
) -> bool:
    """
    Appends an audit event to logs/audit.jsonl in JSONL format.
    Fields: timestamp (ISO), session_id, tool, args (truncated to 500 chars), risk, decision,
    result (truncated to 500 chars), error.
    Returns True if successfully written, False otherwise.
    """
    target_path = Path(log_file)
    try:
        target_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"[Audit Warning] Error creating log directory: {e}")
        return False

    clean_args = None
    if args is not None:
        sanitized_args = sanitize_data(args)
        if isinstance(sanitized_args, str):
            if len(sanitized_args) > 500:
                clean_args = sanitized_args[:500] + "... [truncated]"
            else:
                clean_args = sanitized_args
        else:
            try:
                args_str = json.dumps(sanitized_args, ensure_ascii=False)
            except Exception:
                args_str = str(sanitized_args)
            if len(args_str) > 500:
                clean_args = args_str[:500] + "... [truncated]"
            else:
                clean_args = sanitized_args

    clean_result = None
    if result is not None:
        result_str = str(result)
        if len(result_str) > 500:
            result_str = result_str[:500] + "... [truncated]"
        clean_result = redact_string(result_str)

    clean_error = redact_string(str(error)) if error is not None else None

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "tool": tool,
        "args": clean_args,
        "risk": risk,
        "decision": decision,
        "result": clean_result,
        "error": clean_error,
    }

    try:
        with open(target_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
        return True
    except Exception as e:
        print(f"[Audit Warning] Error writing audit log: {e}")
        return False
