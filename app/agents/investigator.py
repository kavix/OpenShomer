from pathlib import Path
from typing import Optional
from app.models.findings import Finding, FindingType, Severity, InvestigationResult
from app.agents.tools import AgentRepoTools


class InvestigationAgent:
    """Autonomous agent that analyzes prompts, tools, and MCP configs against findings."""

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root
        self.tools = AgentRepoTools(workspace_root)

    def investigate(self, finding: Finding) -> InvestigationResult:
        affected_files = [finding.file]
        root_cause = ""
        recommended_fix = ""
        confidence = 0.95
        risk = finding.severity
        details = {}

        if finding.type == FindingType.OVER_PERMISSIONED_TOOL:
            tools = self.tools.list_tools(finding.file)
            target_tool = next((t for t in tools if t.get("name") == finding.tool), None)
            if target_tool:
                root_cause = f"Tool '{finding.tool}' possesses unrestricted permissions: {target_tool.get('permissions', [])} and requires_approval=False."
                recommended_fix = "Restrict permissions to least-privilege allow-list and require explicit human-in-the-loop (requires_approval: true)."
                details["current_tool_config"] = target_tool
            else:
                root_cause = f"Over-permissioned tool definition in '{finding.file}'."
                recommended_fix = "Apply least-privilege scoping to tool permissions."

        elif finding.type == FindingType.MISSING_APPROVAL_GATE:
            root_cause = f"High-risk action for tool '{finding.tool}' executes without an approval gate."
            recommended_fix = "Enforce `requires_approval: true` and restrict command prefixes."

        elif finding.type == FindingType.PROMPT_INJECTION_SURFACE:
            prompt_data = self.tools.get_prompt_context(finding.file)
            root_cause = f"System prompt in '{finding.file}' lacks instruction defense fences and allows arbitrary user override."
            recommended_fix = "Add strict boundary delimiters and defensive system prompt directives."
            details["prompt_length"] = prompt_data.get("length_chars", 0)

        elif finding.type == FindingType.DATA_EXFILTRATION_PATH:
            root_cause = f"Unrestricted network or secondary tasks in '{finding.file}' allow potential data exfiltration."
            recommended_fix = "Restrict outbound network access and sanitize agent responses."

        elif finding.type == FindingType.HARDCODED_SECRET_IN_PROMPT:
            root_cause = f"Hardcoded credential or API key found in '{finding.file}'."
            recommended_fix = "Remove hardcoded secret and reference environment variables dynamically."

        else:
            root_cause = f"Configuration vulnerability detected in {finding.file}."
            recommended_fix = "Apply security hardening best practices."

        # Check for correlated prompt/tool interactions
        all_files = self.tools.list_files()
        for f in all_files:
            if f.endswith(("system.md", "tools.yaml", "mcp_servers.json")) and f not in affected_files:
                affected_files.append(f)

        return InvestigationResult(
            finding_id=finding.id,
            root_cause=root_cause,
            affected_files=affected_files,
            recommended_fix=recommended_fix,
            confidence=confidence,
            risk=risk,
            details=details
        )
