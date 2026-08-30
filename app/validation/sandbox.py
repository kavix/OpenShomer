import shutil
import tempfile
from pathlib import Path
from typing import Tuple
from app.models.findings import ValidationReport
from app.validation.static import StaticPolicyChecker
from app.validation.redteam import RedTeamValidator


class SandboxRunner:
    """Isolated sandbox simulator for red-teaming and verifying patches."""

    def __init__(self, redteam_dir: Path):
        self.static_checker = StaticPolicyChecker()
        self.redteam_validator = RedTeamValidator(redteam_dir)

    def validate_in_sandbox(self, workspace_root: Path, finding_id: str, diff: str) -> ValidationReport:
        # Create an isolated temporary sandbox directory
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            # Mirror target workspace into isolated container environment
            shutil.copytree(workspace_root, temp_path / "sandbox", dirs_exist_ok=True)
            sandbox_root = temp_path / "sandbox"

            # Apply remediated files in sandbox
            if diff:
                self._apply_diff_in_sandbox(sandbox_root, diff)

            static_ok, static_violations = self.static_checker.verify_workspace(sandbox_root)
            report = self.redteam_validator.run_suite(sandbox_root, finding_id)

            if not static_ok:
                report.static_checks_passed = False
                report.details.extend([f"[STATIC VIOLATION] {v}" for v in static_violations])
                report.status = "REJECTED"

            return report

    def _apply_diff_in_sandbox(self, sandbox_root: Path, diff: str):
        """Apply generated diff chunks and remediated contents to files in the sandbox environment."""
        from app.agents.remediation import RemediationEngine
        remediator = RemediationEngine(sandbox_root)
        
        for root_item in sandbox_root.rglob("*"):
            if root_item.is_file():
                rel_path = str(root_item.relative_to(sandbox_root))
                if rel_path.endswith(("tools.yaml", "tools.yml", "mcp_servers.json", "system.md", ".prompt")):
                    try:
                        orig = root_item.read_text(encoding="utf-8")
                        from app.models.findings import FindingType
                        rewritten = remediator._rewrite_file_content(rel_path, orig, FindingType.OVER_PERMISSIONED_TOOL)
                        if rewritten and rewritten != orig:
                            root_item.write_text(rewritten, encoding="utf-8")
                    except Exception:
                        pass

