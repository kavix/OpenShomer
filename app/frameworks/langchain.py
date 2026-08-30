import re
from pathlib import Path

from app.models.findings import Finding, FindingType, Severity


class LangChainScanner:
    """Scans and analyzes LangChain agent graphs, Tool definitions, and chains."""

    @classmethod
    def scan_langchain_agents(cls, workspace_root: Path) -> list[Finding]:
        findings = []
        finding_idx = 200

        # Scan python agent files
        py_files = list(workspace_root.glob("**/*.py"))
        for pf in py_files:
            if "venv" in str(pf) or ".git" in str(pf) or "tests" in str(pf):
                continue
            try:
                content = pf.read_text(encoding="utf-8")
            except Exception:
                continue

            rel_path = str(pf.relative_to(workspace_root))

            # 1. Unbounded Tool in LangChain
            if "Tool(" in content or "StructuredTool" in content or "@tool" in content:
                if re.search(r"return_direct\s*=\s*True", content) and re.search(r"os\.system|subprocess|eval|exec", content):
                    findings.append(
                        Finding(
                            id=f"LC-{finding_idx:03d}",
                            type=FindingType.OVER_PERMISSIONED_TOOL,
                            severity=Severity.CRITICAL,
                            file=rel_path,
                            issue=f"LangChain tool in '{rel_path}' executes unchecked system subshells with direct return.",
                            repository=workspace_root.name,
                        )
                    )
                    finding_idx += 1

            # 2. AgentExecutor missing max_iterations or execution limits
            if "AgentExecutor(" in content or "create_react_agent" in content or "create_openai_tools_agent" in content:
                if "max_iterations" not in content and "early_stopping_method" not in content:
                    findings.append(
                        Finding(
                            id=f"LC-{finding_idx:03d}",
                            type=FindingType.EXCESSIVE_AGENCY,
                            severity=Severity.MEDIUM,
                            file=rel_path,
                            issue=f"LangChain AgentExecutor in '{rel_path}' lacks `max_iterations` runaway execution guard.",
                            repository=workspace_root.name,
                        )
                    )
                    finding_idx += 1

        return findings
