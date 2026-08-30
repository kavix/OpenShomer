import json
import re
from pathlib import Path

import yaml

from app.models.findings import Finding, FindingType, Severity


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
        findings: list[Finding] = []
        finding_id = 1
        for prompt_file in self._prompt_files(workspace_root):
            content = prompt_file.read_text(encoding="utf-8")
            relative_file = str(prompt_file.relative_to(workspace_root))
            if self._has_unfenced_user_input(content):
                findings.append(self._finding(finding_id, FindingType.DIRECT_PROMPT_INJECTION, Severity.HIGH, relative_file, "User-controlled prompt data is interpolated without an explicit untrusted-input boundary.", workspace_root))
                finding_id += 1
            if self._has_sensitive_data(content):
                findings.append(self._finding(finding_id, FindingType.SENSITIVE_INFORMATION_DISCLOSURE, Severity.CRITICAL, relative_file, "The prompt contains a hardcoded secret or an instruction to disclose sensitive information.", workspace_root))
                finding_id += 1
            if self._has_prompt_leakage_risk(content):
                findings.append(self._finding(finding_id, FindingType.SYSTEM_PROMPT_LEAKAGE, Severity.HIGH, relative_file, "The system prompt lacks a clear instruction preventing disclosure of its hidden instructions.", workspace_root))
                finding_id += 1

        tools_file = workspace_root / "agent/tools.yaml"
        if tools_file.exists():
            try:
                data = yaml.safe_load(tools_file.read_text(encoding="utf-8")) or {}
                for tool in data.get("tools", []):
                    name = str(tool.get("name", ""))
                    permissions = {str(permission).lower() for permission in tool.get("permissions", [])}
                    dangerous = ("shell" in name.lower() or "subprocess" in name.lower() or "sql" in name.lower() or any(token in permissions for token in ("shell:unrestricted", "filesystem:write")))
                    bounded = bool(tool.get("parameter_bounds") or tool.get("requires_approval"))
                    if dangerous and not bounded:
                        findings.append(self._finding(finding_id, FindingType.EXCESSIVE_AGENCY, Severity.HIGH, "agent/tools.yaml", f"Tool '{name}' exposes a dangerous capability without approval or parameter bounds.", workspace_root, tool=name))
                        finding_id += 1
            except (OSError, yaml.YAMLError):
                pass
        return findings

    @staticmethod
    def _prompt_files(workspace_root: Path) -> list[Path]:
        prompt_root = workspace_root / "prompts"
        if not prompt_root.exists():
            return []
        return [path for path in prompt_root.rglob("*") if path.is_file() and path.suffix in {".md", ".prompt", ".txt"}]

    @staticmethod
    def _has_unfenced_user_input(content: str) -> bool:
        placeholder = re.search(r"(?:\{\{|\{)\s*(?:user(?:[_-]input)?|input|query|message)\b", content, re.IGNORECASE)
        if not placeholder:
            return False
        return not re.search(r"(?:untrusted|user input boundary|begin_user|end_user|<user_input>)", content, re.IGNORECASE)

    @staticmethod
    def _has_sensitive_data(content: str) -> bool:
        secret = re.search(r"(?:sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|(?:api[_-]?key|secret|password)\s*[:=]\s*['\"]?[^\s'\"]+)", content, re.IGNORECASE)
        disclosure = re.search(r"(?:reveal|print|return|include).{0,40}(?:api key|password|secret|ssn|social security)", content, re.IGNORECASE | re.DOTALL)
        return bool(secret or disclosure)

    @staticmethod
    def _has_prompt_leakage_risk(content: str) -> bool:
        has_system_instruction = bool(re.search(r"(?:system prompt|system instructions|you are an assistant)", content, re.IGNORECASE))
        has_defense = bool(re.search(r"(?:do not|never|must not).{0,40}(?:reveal|disclose|hidden instructions|system prompt)", content, re.IGNORECASE | re.DOTALL))
        return has_system_instruction and not has_defense

    @staticmethod
    def _finding(number: int, finding_type: FindingType, severity: Severity, file: str, issue: str, workspace_root: Path, tool: str | None = None) -> Finding:
        return Finding(id=f"SHOMER-OWASP-{number:03d}", type=finding_type, severity=severity, file=file, tool=tool, issue=issue, repository=workspace_root.name)
