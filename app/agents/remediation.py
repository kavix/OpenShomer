import difflib
import json
import yaml
from pathlib import Path
from typing import List, Tuple, Optional
from app.models.findings import InvestigationResult, RemediationResult, FindingType
from app.validation.guardrails import PatchGuardrails
from app.agents.providers import LLMProvider, get_llm_provider


class RemediationEngine:
    """Generates minimal safe rewrites for prompts, tool definitions, and MCP configs."""

    def __init__(self, workspace_root: Path, llm_provider: Optional[LLMProvider] = None):
        self.workspace_root = workspace_root
        self.guardrails = PatchGuardrails()
        self.llm_provider = llm_provider or get_llm_provider()

    def remediate(self, investigation: InvestigationResult, finding_type: FindingType) -> RemediationResult:
        modified_files: List[str] = []
        unified_diffs: List[str] = []

        for rel_file in investigation.affected_files:
            file_path = self.workspace_root / rel_file
            if not file_path.exists() or not file_path.is_file():
                continue

            original_content = file_path.read_text(encoding="utf-8")
            rewritten_content = self._rewrite_file_content(rel_file, original_content, finding_type)

            if original_content != rewritten_content:
                diff_lines = list(difflib.unified_diff(
                    original_content.splitlines(keepends=True),
                    rewritten_content.splitlines(keepends=True),
                    fromfile=f"a/{rel_file}",
                    tofile=f"b/{rel_file}"
                ))
                if diff_lines:
                    unified_diffs.append("".join(diff_lines))
                    modified_files.append(rel_file)

        full_diff = "\n".join(unified_diffs)

        # Apply guardrails
        is_valid, reason = self.guardrails.validate_patch(
            diff=full_diff,
            allowed_files=investigation.affected_files,
            max_lines=150
        )

        return RemediationResult(
            finding_id=investigation.finding_id,
            diff=full_diff,
            modified_files=modified_files,
            guardrails_passed=is_valid,
            rejection_reason=reason if not is_valid else None
        )

    def _rewrite_file_content(self, filename: str, content: str, finding_type: FindingType) -> str:
        from app.qoder.diff_synthesizer import DiffSynthesizer
        if filename.endswith("tools.yaml") or filename.endswith("tools.yml"):
            rewritten, _ = DiffSynthesizer.synthesize_tool_yaml(content)
            return rewritten
        elif filename.endswith("mcp_servers.json"):
            rewritten, _ = DiffSynthesizer.synthesize_mcp_json(content)
            return rewritten
        elif filename.endswith("system.md") or filename.endswith(".prompt"):
            rewritten, _ = DiffSynthesizer.synthesize_prompt_fence(content, filename=filename)
            return rewritten
        return content
