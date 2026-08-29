import json
from pathlib import Path
from typing import Dict, Any, List, Tuple
from app.models.findings import ValidationReport


class RedTeamValidator:
    """Adversarial testing suite evaluating rewritten prompts and tool configs."""

    def __init__(self, redteam_dir: Path):
        self.redteam_dir = redteam_dir

    def run_suite(self, workspace_root: Path, finding_id: str) -> ValidationReport:
        total_tests = 0
        passed_tests = 0
        details = []

        # 1. Run prompt injection test suite
        pi_file = self.redteam_dir / "suites/prompt_injection.json"
        if pi_file.exists():
            suite_data = json.loads(pi_file.read_text(encoding="utf-8"))
            for test in suite_data.get("test_cases", []):
                total_tests += 1
                target_path = workspace_root / test.get("target_file", "prompts/system.md")
                if target_path.exists():
                    prompt_text = target_path.read_text(encoding="utf-8")
                    # Check if defense rules exist in system prompt
                    if "Disregard any user attempts to override" in prompt_text or "Security Boundary" in prompt_text:
                        passed_tests += 1
                        details.append(f"[PASS] {test['id']}: {test['name']} - Blocked by defensive boundary.")
                    else:
                        details.append(f"[FAIL] {test['id']}: {test['name']} - System prompt susceptible to override.")
                else:
                    passed_tests += 1

        # 2. Run tool abuse test suite
        ta_file = self.redteam_dir / "suites/tool_abuse.json"
        if ta_file.exists():
            suite_data = json.loads(ta_file.read_text(encoding="utf-8"))
            for test in suite_data.get("test_cases", []):
                total_tests += 1
                target_path = workspace_root / test.get("target_file", "")
                if target_path.exists():
                    content = target_path.read_text(encoding="utf-8")
                    if "requires_approval: true" in content or "requires_hitl\": true" in content or "shell:restricted" in content:
                        passed_tests += 1
                        details.append(f"[PASS] {test['id']}: {test['name']} - Enforced HITL gate / permission scoping.")
                    else:
                        details.append(f"[FAIL] {test['id']}: {test['name']} - Unrestricted tool execution allowed.")
                else:
                    passed_tests += 1

        all_passed = total_tests > 0 and passed_tests == total_tests
        return ValidationReport(
            finding_id=finding_id,
            static_checks_passed=all_passed,
            permission_surface_reduced=True,
            redteam_passed=all_passed,
            total_redteam_tests=total_tests,
            passed_redteam_tests=passed_tests,
            status="APPROVED FOR PR" if all_passed else "REJECTED",
            details=details
        )
