import json
from pathlib import Path

import yaml

from app.models.findings import Finding


class StaticPolicyChecker:
    """Static checks for permissions, approval gates, and sensitive tokens."""

    def verify_workspace(self, workspace_root: Path) -> tuple[bool, list[str]]:
        violations = [finding.issue for finding in self.detect_findings(workspace_root)]

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
                violations.append(f"Failed to parse tools.yaml: {e!s}")

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
                violations.append(f"Failed to parse mcp_servers.json: {e!s}")

        return len(violations) == 0, violations

    def detect_findings(self, workspace_root: Path) -> list[Finding]:
        """Return structured deterministic findings for OWASP LLM categories."""
        from app.validation.owasp_rules import RULE_REGISTRY

        findings: list[Finding] = []
        finding_id = 1

        # Collect all files to scan
        files_to_scan = self._prompt_files(workspace_root)
        tools_file = workspace_root / "agent/tools.yaml"
        if tools_file.exists():
            files_to_scan.append(tools_file)

        # Also include python files for AST scanning
        for py_file in workspace_root.rglob("*.py"):
            if ".venv" not in py_file.parts and "tests" not in py_file.parts:
                files_to_scan.append(py_file)

        for file_path in files_to_scan:
            if not file_path.exists() or not file_path.is_file():
                continue

            try:
                content = file_path.read_text(encoding="utf-8")
            except Exception:
                continue

            for rule_class in RULE_REGISTRY.values():
                new_findings = rule_class.detect(file_path, content, workspace_root, finding_id)
                if new_findings:
                    findings.extend(new_findings)
                    finding_id += len(new_findings)

        return findings

    @staticmethod
    def _prompt_files(workspace_root: Path) -> list[Path]:
        prompt_root = workspace_root / "prompts"
        if not prompt_root.exists():
            return []
        return [path for path in prompt_root.rglob("*") if path.is_file() and path.suffix in {".md", ".prompt", ".txt"}]
