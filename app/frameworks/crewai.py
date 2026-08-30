import re
from pathlib import Path
from typing import List, Dict, Any
from app.models.findings import Finding, FindingType, Severity


class CrewAIScanner:
    """Scans and analyzes CrewAI Agents, Tasks, and Crews for delegation & permission risks."""

    @classmethod
    def scan_crewai_agents(cls, workspace_root: Path) -> List[Finding]:
        findings = []
        finding_idx = 400

        files = list(workspace_root.glob("**/*.py")) + list(workspace_root.glob("**/*.yaml"))
        for f in files:
            if "venv" in str(f) or ".git" in str(f) or "tests" in str(f):
                continue
            try:
                content = f.read_text(encoding="utf-8")
            except Exception:
                continue

            rel_path = str(f.relative_to(workspace_root))

            # 1. Unbounded Delegation
            if "allow_delegation" in content:
                if re.search(r"allow_delegation\s*[:=]\s*True", content, re.IGNORECASE):
                    # Check if agent has dangerous tools attached
                    if re.search(r"tools\s*[:=]\s*\[.*?(?:shell|bash|terminal|exec|sql).*?\]", content, re.IGNORECASE | re.DOTALL):
                        findings.append(
                            Finding(
                                id=f"CREW-{finding_idx:03d}",
                                type=FindingType.EXCESSIVE_AGENCY,
                                severity=Severity.HIGH,
                                file=rel_path,
                                issue=f"CrewAI Agent in '{rel_path}' combines unconstrained delegation (allow_delegation=True) with dangerous tool execution capabilities.",
                                repository=workspace_root.name,
                            )
                        )
                        finding_idx += 1

        return findings
