import re
from pathlib import Path

from app.models.findings import Finding, FindingType, Severity


class LlamaIndexScanner:
    """Scans and analyzes LlamaIndex FunctionTools, ReActAgent, and QueryEngine tools."""

    @classmethod
    def scan_llamaindex_agents(cls, workspace_root: Path) -> list[Finding]:
        findings = []
        finding_idx = 300

        py_files = list(workspace_root.glob("**/*.py"))
        for pf in py_files:
            if "venv" in str(pf) or ".git" in str(pf) or "tests" in str(pf):
                continue
            try:
                content = pf.read_text(encoding="utf-8")
            except Exception:
                continue

            rel_path = str(pf.relative_to(workspace_root))

            # 1. Unbounded FunctionTool
            if "FunctionTool.from_defaults" in content:
                if re.search(r"fn\s*=\s*(?:exec|eval|os\.system|subprocess)", content):
                    findings.append(
                        Finding(
                            id=f"LLAMA-{finding_idx:03d}",
                            type=FindingType.OVER_PERMISSIONED_TOOL,
                            severity=Severity.CRITICAL,
                            file=rel_path,
                            issue=f"LlamaIndex FunctionTool in '{rel_path}' exposes dangerous execution primitives without validation.",
                            repository=workspace_root.name,
                        )
                    )
                    finding_idx += 1

            # 2. ReActAgent missing max_iterations / runaway loops
            if "ReActAgent.from_tools" in content or "OpenAIAgent.from_tools" in content:
                if "max_iterations" not in content:
                    findings.append(
                        Finding(
                            id=f"LLAMA-{finding_idx:03d}",
                            type=FindingType.EXCESSIVE_AGENCY,
                            severity=Severity.MEDIUM,
                            file=rel_path,
                            issue=f"LlamaIndex Agent in '{rel_path}' initialized without `max_iterations` runaway loop safeguard.",
                            repository=workspace_root.name,
                        )
                    )
                    finding_idx += 1

        return findings
