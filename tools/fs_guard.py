"""Filesystem security guard: workspace isolation, path validation, and size limits."""

import os
import re
from pathlib import Path

from config import get_workspace_dir
from core.paths import DATA_DIR, LOGS_DIR, PROJECT_ROOT

RESERVED_DEVICE_NAMES = {
    "con", "prn", "aux", "nul",
    "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
    "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
}


class FSGuardError(Exception):
    """Base exception for filesystem guard errors."""
    pass


class WorkspaceSecurityError(FSGuardError):
    """Raised when workspace configuration violates security boundaries."""
    pass


class PathValidationError(FSGuardError):
    """Raised when a user-supplied path violates security rules."""
    pass


class WriteSizeLimitError(FSGuardError):
    """Raised when data to write exceeds the limit."""
    pass


def _is_same_or_subpath(target: Path, base: Path) -> bool:
    """Checks if target is equal to base or a descendant of base (case-insensitive)."""
    try:
        common = os.path.commonpath([str(target).lower(), str(base).lower()])
        return common == str(base).lower()
    except ValueError:
        # Different drives or incompatible paths
        return False


def resolve_workspace(workspace_path: str | Path | None = None) -> Path:
    """
    Resolves the workspace directory with realpath and creates it if missing.
    Refuses to start / raises WorkspaceSecurityError if the workspace is inside
    the project root, equals it, or is a parent of it.
    """
    if workspace_path is None:
        workspace_path = get_workspace_dir()

    ws_path = Path(os.path.realpath(workspace_path))
    proj_root = Path(os.path.realpath(PROJECT_ROOT))

    ws_lower = str(ws_path).lower()
    proj_lower = str(proj_root).lower()

    if ws_lower == proj_lower:
        raise WorkspaceSecurityError(
            f"Workspace path cannot be the same as project root: {ws_path}"
        )

    if _is_same_or_subpath(ws_path, proj_root):
        raise WorkspaceSecurityError(
            f"Workspace path cannot be inside project root: {ws_path} is inside {proj_root}"
        )

    if _is_same_or_subpath(proj_root, ws_path):
        raise WorkspaceSecurityError(
            f"Workspace path cannot be a parent of project root: {ws_path} contains {proj_root}"
        )

    # Security check passed; create directory if it does not exist
    ws_path.mkdir(parents=True, exist_ok=True)
    return Path(os.path.realpath(ws_path))


def validate_path(
    user_path: str | Path,
    workspace: str | Path | None = None,
    allow_root: bool = False,
) -> Path:
    """
    Validates user_path against workspace boundaries and security rules.
    Returns resolved canonical Path or raises PathValidationError.

    IMPORTANT: Callers MUST pass the returned resolved Path object to all subsequent
    file operations, NEVER the original user-supplied path string, to guarantee that
    canonicalization, symlink resolution, and security boundaries are strictly enforced.

    Rules:
    - Realpath (symlink/junction follow) must be strictly inside the workspace.
    - Reject ".." escaping the workspace.
    - Reject absolute paths outside the workspace.
    - Reject UNC paths (\\\\server\\share, //server/share, mixed \\/ or /\\).
    - Reject device / verbatim paths (\\\\?\\, \\\\.\\).
    - Reject drive-letter changes.
    - Reject NTFS alternate data streams (another ':' after drive letter).
    - Reject Windows reserved device names (CON, NUL, AUX, PRN, COM1-9, LPT1-9) with or without extension.
    - Reject path components ending with dot ('.') or space (' ').
    - Reject 8.3 short name patterns (~ followed by digit).
    - Case-insensitive comparison on Windows.
    - Always reject paths that resolve into or target project root, .git (exact), or any name starting with .env.
    - Deny workspace root itself unless allow_root=True.
    """
    if user_path is None:
        raise PathValidationError("Path cannot be None")

    raw_path_str = str(user_path)
    if not raw_path_str.strip():
        raise PathValidationError("Path cannot be empty")

    # 1. Reject UNC, device, or verbatim paths
    # Replace '/' with '\\' first to catch mixed separators (e.g. \\/, /\\, //)
    normalized_separators = raw_path_str.replace("/", "\\")
    if normalized_separators.startswith("\\\\"):
        raise PathValidationError(
            f"UNC, device, or verbatim paths are not allowed: {user_path}"
        )

    # 2. Reject NTFS Alternate Data Streams (':' after drive letter or anywhere in relative path)
    has_drive = bool(re.match(r"^[a-zA-Z]:", raw_path_str))
    colon_check_str = raw_path_str[2:] if has_drive else raw_path_str
    if ":" in colon_check_str:
        raise PathValidationError(
            f"NTFS alternate data streams are not allowed: {user_path}"
        )

    # Reject drive-relative paths without slash (e.g. C:foo)
    if re.match(r"^[a-zA-Z]:[^\\/]", raw_path_str):
        raise PathValidationError(
            f"Drive-relative paths without slash are not allowed: {user_path}"
        )

    # 3. Component-level checks on input path
    components = [c for c in re.split(r"[\\/]+", raw_path_str) if c]
    check_components = (
        components[1:]
        if (components and re.match(r"^[a-zA-Z]:$", components[0]))
        else components
    )

    for comp in check_components:
        comp_lower = comp.lower()

        # Check protected names: exact .git, or starting with .env
        if comp_lower == ".git" or comp_lower.startswith(".env"):
            raise PathValidationError(
                f"Access to protected name '{comp}' is denied: {user_path}"
            )

        # Check reserved DOS device names (with or without extension)
        base_name = comp_lower.split(".")[0]
        if base_name in RESERVED_DEVICE_NAMES or comp_lower in RESERVED_DEVICE_NAMES:
            raise PathValidationError(
                f"Reserved device name '{comp}' is not allowed: {user_path}"
            )

        # Check trailing dot or space (do not normalize, reject!)
        if comp not in (".", "..") and (comp.endswith(".") or comp.endswith(" ")):
            raise PathValidationError(
                f"Path component cannot end with dot or space: '{comp}' in {user_path}"
            )

        # Check 8.3 short name patterns (~ followed by digit)
        if re.search(r"~\d", comp):
            raise PathValidationError(
                f"Short name (8.3) patterns are not allowed: '{comp}' in {user_path}"
            )

    # 4. Resolve workspace
    ws_resolved = resolve_workspace(workspace)
    ws_drive = os.path.splitdrive(str(ws_resolved))[0].lower()

    # 5. Reject drive letter changes
    user_drive = os.path.splitdrive(raw_path_str)[0]
    if user_drive and user_drive.lower() != ws_drive:
        raise PathValidationError(
            f"Drive letter change not allowed: '{user_drive}' does not match workspace drive '{ws_drive}'"
        )

    # 6. Target path resolution
    if os.path.isabs(raw_path_str):
        target = Path(raw_path_str)
    else:
        target = ws_resolved / raw_path_str

    resolved_path = Path(os.path.realpath(target))

    # 7. Realpath must be strictly within workspace (case-insensitive)
    try:
        common = os.path.commonpath([str(resolved_path).lower(), str(ws_resolved).lower()])
        is_inside = (common == str(ws_resolved).lower())
    except ValueError:
        is_inside = False

    if not is_inside:
        raise PathValidationError(
            f"Path '{user_path}' resolves outside workspace boundary: {resolved_path}"
        )

    # 8. Check workspace root access
    if str(resolved_path).lower() == str(ws_resolved).lower() and not allow_root:
        raise PathValidationError(
            f"Access to workspace root is denied unless allow_root=True: {user_path}"
        )

    # 9. Reject paths resolving into project root, .git, .env*, data/, logs/
    proj_root = Path(os.path.realpath(PROJECT_ROOT))
    protected_targets = [
        proj_root,
        proj_root / ".git",
        proj_root / ".env",
        DATA_DIR,
        LOGS_DIR,
    ]
    for pt in protected_targets:
        resolved_pt = Path(os.path.realpath(pt))
        try:
            common = os.path.commonpath([str(resolved_path).lower(), str(resolved_pt).lower()])
            if common == str(resolved_pt).lower():
                raise PathValidationError(
                    f"Path resolves into protected project area: {resolved_path}"
                )
        except ValueError:
            pass

    # 10. Reject resolved path components matching protected names or reserved device names
    for part in resolved_path.parts:
        part_lower = part.lower()
        if part_lower == ".git" or part_lower.startswith(".env"):
            raise PathValidationError(
                f"Resolved path contains protected name '{part}': {resolved_path}"
            )
        base_part = part_lower.split(".")[0]
        if base_part in RESERVED_DEVICE_NAMES or part_lower in RESERVED_DEVICE_NAMES:
            raise PathValidationError(
                f"Resolved path contains reserved device name '{part}': {resolved_path}"
            )

    return resolved_path


def truncate_result(text: str, limit: int = 20000) -> str:
    """
    Truncates text if length exceeds limit and appends '[truncated]' marker.
    """
    if not isinstance(text, str):
        text = str(text)
    if len(text) > limit:
        return text[:limit] + "[truncated]"
    return text


def check_write_size(data: str | bytes | bytearray, limit: int = 1_000_000) -> None:
    """
    Validates that the size of data to write does not exceed limit bytes.
    Raises WriteSizeLimitError if exceeded.
    """
    if isinstance(data, str):
        size = len(data.encode("utf-8"))
    elif isinstance(data, (bytes, bytearray)):
        size = len(data)
    else:
        raise TypeError(f"Expected str, bytes, or bytearray, got {type(data).__name__}")

    if size > limit:
        raise WriteSizeLimitError(
            f"Write data size ({size} bytes) exceeds the limit of {limit} bytes"
        )
