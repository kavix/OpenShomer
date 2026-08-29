import json
import yaml
from pathlib import Path
from typing import Dict, Any, Tuple, List


class StaticPolicyChecker:
    """Static checks for permissions, approval gates, and sensitive tokens."""

    def verify_workspace(self, workspace_root: Path) -> Tuple[bool, List[str]]:
        violations = []

        tools_file = workspace_root / "agent/tools.yaml"
        if tools_file.exists():
            try:
                data = yaml.safe_load(tools_file.read_text(encoding="utf-8"))
                for tool in data.get("tools", []):
                    if "shell:unrestricted" in tool.get("permissions", []):
                        violations.append(f"Tool '{tool.get('name')}' has shell:unrestricted.")
                    if not tool.get("requires_approval", False) and "shell" in tool.get("name", ""):
                        violations.append(f"Tool '{tool.get('name')}' lacks requires_approval=True.")
            except Exception as e:
                violations.append(f"Failed to parse tools.yaml: {str(e)}")

        mcp_file = workspace_root / "mcp/mcp_servers.json"
        if mcp_file.exists():
            try:
                data = json.loads(mcp_file.read_text(encoding="utf-8"))
                for name, srv in data.get("mcpServers", {}).items():
                    if srv.get("permissions", {}).get("allowAllPaths") is True:
                        violations.append(f"MCP server '{name}' allows all filesystem paths.")
                    env_vals = str(srv.get("env", {}))
                    if "sk_live_" in env_vals or "secret_" in env_vals:
                        violations.append(f"MCP server '{name}' contains raw hardcoded secret tokens.")
            except Exception as e:
                violations.append(f"Failed to parse mcp_servers.json: {str(e)}")

        return len(violations) == 0, violations
