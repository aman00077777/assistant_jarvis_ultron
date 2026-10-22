"""Policy mapping and allowlist for filesystem MCP tools."""

from dataclasses import dataclass


@dataclass(frozen=True)
class FSToolPolicy:
    mcp_name: str
    model_name: str
    risk: str = "low"
    reversible: bool = True
    returns_untrusted: bool = True


# Explicit allowlist of supported read-only filesystem tools
# Only these 7 tools are permitted; all write/edit/delete/unknown tools are excluded.
FS_POLICY_MAP: dict[str, FSToolPolicy] = {
    "read_text_file": FSToolPolicy(
        mcp_name="read_text_file",
        model_name="fs_read_text_file",
        risk="low",
        reversible=True,
        returns_untrusted=True,
    ),
    "read_multiple_files": FSToolPolicy(
        mcp_name="read_multiple_files",
        model_name="fs_read_multiple_files",
        risk="low",
        reversible=True,
        returns_untrusted=True,
    ),
    "list_directory": FSToolPolicy(
        mcp_name="list_directory",
        model_name="fs_list_directory",
        risk="low",
        reversible=True,
        returns_untrusted=True,
    ),
    "list_directory_with_sizes": FSToolPolicy(
        mcp_name="list_directory_with_sizes",
        model_name="fs_list_directory_with_sizes",
        risk="low",
        reversible=True,
        returns_untrusted=True,
    ),
    "directory_tree": FSToolPolicy(
        mcp_name="directory_tree",
        model_name="fs_directory_tree",
        risk="low",
        reversible=True,
        returns_untrusted=True,
    ),
    "search_files": FSToolPolicy(
        mcp_name="search_files",
        model_name="fs_search_files",
        risk="low",
        reversible=True,
        returns_untrusted=True,
    ),
    "get_file_info": FSToolPolicy(
        mcp_name="get_file_info",
        model_name="fs_get_file_info",
        risk="low",
        reversible=True,
        returns_untrusted=True,
    ),
}

# Reverse map: model_name -> FSToolPolicy
MODEL_TO_FS_POLICY: dict[str, FSToolPolicy] = {
    policy.model_name: policy for policy in FS_POLICY_MAP.values()
}

ALLOWED_MCP_TOOLS: set[str] = set(FS_POLICY_MAP.keys())
ALLOWED_MODEL_TOOLS: set[str] = set(MODEL_TO_FS_POLICY.keys())
