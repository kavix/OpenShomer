import difflib
from pathlib import Path

from app.agents.providers import LLMProvider, get_llm_provider
from app.models.findings import FindingType, InvestigationResult, RemediationResult
from app.validation.guardrails import PatchGuardrails


class RemediationEngine:
    """Generates minimal safe rewrites for prompts, tool definitions, and MCP configs."""

    def __init__(self, workspace_root: Path, llm_provider: LLMProvider | None = None):
        self.workspace_root = workspace_root
        self.guardrails = PatchGuardrails()
        self.llm_provider = llm_provider or get_llm_provider()

    def remediate(self, investigation: InvestigationResult, finding_type: FindingType) -> RemediationResult:
        modified_files: list[str] = []
        unified_diffs: list[str] = []
        rewritten_contents: dict[str, str] = {}

        for rel_file in investigation.affected_files:
            file_path = self.workspace_root / rel_file
            if not file_path.exists() or not file_path.is_file():
                continue

            original_content = file_path.read_text(encoding="utf-8")
            rewritten_content = self._rewrite_file_content(rel_file, original_content, finding_type)

            if original_content != rewritten_content:
                diff_lines = list(
                    difflib.unified_diff(
                        original_content.splitlines(keepends=True),
                        rewritten_content.splitlines(keepends=True),
                        fromfile=f"a/{rel_file}",
                        tofile=f"b/{rel_file}",
                    )
                )
                if diff_lines:
                    unified_diffs.append("".join(diff_lines))
                    modified_files.append(rel_file)
                    rewritten_contents[rel_file] = rewritten_content

        full_diff = "\n".join(unified_diffs)

        # Apply guardrails
        is_valid, reason = self.guardrails.validate_patch(
            diff=full_diff, allowed_files=investigation.affected_files, max_lines=300
        )

        return RemediationResult(
            finding_id=investigation.finding_id,
            diff=full_diff,
            modified_files=modified_files,
            guardrails_passed=is_valid,
            rejection_reason=reason if not is_valid else None,
            rewritten_contents=rewritten_contents,
        )

    def _rewrite_file_content(self, filename: str, content: str, finding_type: FindingType) -> str:
        from app.models.findings import Finding, Severity
        from app.qoder.diff_synthesizer import DiffSynthesizer
        from app.qoder.ide import QoderIDE
        from app.validation.owasp_rules import RULE_REGISTRY

        # Route OWASP findings via registry
        if finding_type in RULE_REGISTRY:
            dummy_finding = Finding(
                id="dummy",
                type=finding_type,
                severity=Severity.HIGH,
                file=filename,
                issue="dummy",
                repository="dummy",
                tool=None,
            )
            # Find the tool name if this is LLM06 and it's a tools.yaml
            if finding_type == FindingType.EXCESSIVE_AGENCY and filename.endswith(("tools.yaml", "tools.yml")):
                import yaml

                try:
                    data = yaml.safe_load(content)
                    for tool in data.get("tools", []):
                        if tool.get("requires_approval") is not True:
                            dummy_finding.tool = tool.get("name")
                            break
                except Exception:
                    pass

            return RULE_REGISTRY[finding_type].synthesize_patch(dummy_finding, content)

        ide = QoderIDE(self.workspace_root)
        res = ide.generate_remediation_diff(filename)
        if res.get("rewritten_content"):
            return res["rewritten_content"]

        if filename.endswith(("tools.yaml", "tools.yml")):
            rewritten, _ = DiffSynthesizer.synthesize_tool_yaml(content)
            return rewritten
        elif filename.endswith("mcp_servers.json"):
            rewritten, _ = DiffSynthesizer.synthesize_mcp_json(content)
            return rewritten
        elif filename.endswith(("system.md", ".prompt")) or "prompt" in filename:
            rewritten, _ = DiffSynthesizer.synthesize_prompt_fence(content, filename=filename)
            return rewritten
        return content
