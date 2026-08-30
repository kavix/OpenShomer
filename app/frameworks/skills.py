import re
import json
import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional
from app.models.findings import Finding, FindingType, Severity


class SkillFileScanner:
    """Scans and analyzes agent skill files (SKILL.md, skills/*.yaml) for security misconfigurations."""

    @classmethod
    def scan_skills(cls, workspace_root: Path) -> List[Finding]:
        findings = []
        finding_idx = 100

        # Scan for SKILL.md and skills directory without duplicates
        all_skills = set(workspace_root.glob("**/SKILL.md")) | set(workspace_root.glob("**/skills/**/*.md")) | set(workspace_root.glob("**/skills/**/*.yaml"))
        skill_files = sorted([f for f in all_skills if "venv" not in str(f) and ".git" not in str(f)])
        for sf in skill_files:
            rel_path = str(sf.relative_to(workspace_root))
            content = sf.read_text(encoding="utf-8")

            # Check for arbitrary command execution without boundaries
            if re.search(r"(?:bash|sh|cmd|exec|eval|system)\s*:\s*unrestricted", content, re.IGNORECASE) or "run_command" in content and "unrestricted" in content:
                findings.append(
                    Finding(
                        id=f"SKILL-{finding_idx:03d}",
                        type=FindingType.OVER_PERMISSIONED_TOOL,
                        severity=Severity.HIGH,
                        file=rel_path,
                        tool=sf.stem,
                        issue=f"Skill file '{rel_path}' defines unrestricted shell/command execution capability.",
                        repository=workspace_root.name,
                    )
                )
                finding_idx += 1

            # Check for prompt injection in skill instructions
            if re.search(r"ignore previous instructions|execute without validation|bypass security", content, re.IGNORECASE):
                findings.append(
                    Finding(
                        id=f"SKILL-{finding_idx:03d}",
                        type=FindingType.PROMPT_INJECTION_SURFACE,
                        severity=Severity.CRITICAL,
                        file=rel_path,
                        issue=f"Skill file '{rel_path}' contains malicious or unsafe prompt override directives.",
                        repository=workspace_root.name,
                    )
                )
                finding_idx += 1

        return findings
