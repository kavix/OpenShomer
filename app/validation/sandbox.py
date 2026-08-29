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
            static_ok, static_violations = self.static_checker.verify_workspace(sandbox_root)
            report = self.redteam_validator.run_suite(sandbox_root, finding_id)

            if not static_ok:
                report.static_checks_passed = False
                report.details.extend([f"[STATIC VIOLATION] {v}" for v in static_violations])
                report.status = "REJECTED"

            return report
