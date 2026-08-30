import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from app.agents.investigator import InvestigationAgent
from app.agents.providers import LLMProvider, get_llm_provider
from app.models.findings import (
    InvestigationResult,
)
from app.mulerun.runtime import MuleRunRuntime
from app.qoder.ide import QoderIDE
from app.validation.sandbox import SandboxRunner


class QoderWorkStep(BaseModel):
    step_name: str
    status: str
    details: dict[str, Any] = Field(default_factory=dict)
    duration_ms: float = 0.0


class QoderWorkLifecycleReport(BaseModel):
    workflow_id: str
    state: str  # Trigger -> Investigate -> Action -> Resolved (or Failed)
    steps: list[QoderWorkStep] = Field(default_factory=list)
    findings_count: int = 0
    patches_applied: list[str] = Field(default_factory=list)
    redteam_passed: bool = False
    resolved: bool = False
    total_time_ms: float = 0.0


class QoderWorkAgent:
    """QoderWork: Autonomous Desktop AI Agent for End-to-End Security Remediation.
    
    Implements continuous planning & autonomous execution loop:
    Trigger -> Investigate -> Action -> Resolved.
    """

    def __init__(
        self,
        workspace_root: Path,
        llm_provider: LLMProvider | None = None,
        mulerun_runtime: MuleRunRuntime | None = None,
        redteam_dir: Path | None = None,
    ):
        self.workspace_root = Path(workspace_root)
        self.llm_provider = llm_provider or get_llm_provider()
        self.mulerun = mulerun_runtime or MuleRunRuntime(llm_provider=self.llm_provider)
        self.investigator = InvestigationAgent(workspace_root=self.workspace_root, llm_provider=self.llm_provider)
        self.qoder = QoderIDE(workspace_root=self.workspace_root)
        rt_dir = redteam_dir.resolve() if redteam_dir else Path(__file__).resolve().parent.parent.parent / "redteam"
        self.sandbox = SandboxRunner(rt_dir)

    def run_lifecycle(self, max_retries: int = 2) -> QoderWorkLifecycleReport:
        """Run the complete autonomous Trigger -> Investigate -> Action -> Resolved workflow."""
        start_time = time.time()
        wf_id = f"qw-{int(start_time)}"
        steps: list[QoderWorkStep] = []

        # ----------------------------------------------------
        # Stage 1: TRIGGER
        # ----------------------------------------------------
        t0 = time.time()
        from app.cli import scan_workspace
        findings = scan_workspace(self.workspace_root)
        t_trigger = (time.time() - t0) * 1000
        
        steps.append(QoderWorkStep(
            step_name="Trigger",
            status="success",
            details={"findings_found": len(findings), "finding_ids": [f.id for f in findings]},
            duration_ms=t_trigger,
        ))
        self.mulerun.emit_telemetry("qoderwork_lifecycle", "trigger_completed", {"findings_count": len(findings)})

        if not findings:
            total_duration = (time.time() - start_time) * 1000
            return QoderWorkLifecycleReport(
                workflow_id=wf_id,
                state="Resolved",
                steps=steps,
                findings_count=0,
                redteam_passed=True,
                resolved=True,
                total_time_ms=total_duration,
            )

        # ----------------------------------------------------
        # Stage 2: INVESTIGATE
        # ----------------------------------------------------
        t0 = time.time()
        investigations: list[InvestigationResult] = []
        for finding in findings:
            inv = self.investigator.investigate(finding)
            investigations.append(inv)
        t_inv = (time.time() - t0) * 1000

        steps.append(QoderWorkStep(
            step_name="Investigate",
            status="success",
            details={"investigations_completed": len(investigations)},
            duration_ms=t_inv,
        ))
        self.mulerun.emit_telemetry("qoderwork_lifecycle", "investigate_completed", {"investigations_count": len(investigations)})

        # ----------------------------------------------------
        # Stage 3: ACTION (Synthesis)
        # ----------------------------------------------------
        t0 = time.time()
        applied_patches: list[str] = []
        full_diff_chunks: list[str] = []
        files_to_remediate = set()
        for inv in investigations:
            for f in inv.affected_files:
                files_to_remediate.add(f)

        for rel_file in files_to_remediate:
            qoder_res = self.qoder.generate_remediation_diff(rel_file)
            if qoder_res.get("success") and qoder_res.get("diff"):
                full_diff_chunks.append(qoder_res["diff"])
                applied_patches.append(rel_file)

        combined_diff = "\n".join(full_diff_chunks)
        t_action = (time.time() - t0) * 1000
        steps.append(QoderWorkStep(
            step_name="Action",
            status="success",
            details={"applied_files": applied_patches},
            duration_ms=t_action,
        ))
        self.mulerun.emit_telemetry("qoderwork_lifecycle", "action_completed", {"applied_files": applied_patches})

        # ----------------------------------------------------
        # Stage 4: RESOLVED (Adversarial Verification & Telemetry)
        # ----------------------------------------------------
        t0 = time.time()
        finding_id = findings[0].id if findings else "SHOMER-001"
        validation_res = self.sandbox.validate_in_sandbox(
            workspace_root=self.workspace_root,
            finding_id=finding_id,
            diff=combined_diff,
        )
        t_resolve = (time.time() - t0) * 1000

        all_passed = validation_res.redteam_passed
        steps.append(QoderWorkStep(
            step_name="Resolved",
            status="success" if all_passed else "failed",
            details={
                "all_passed": all_passed,
                "static_passed": validation_res.static_checks_passed,
                "redteam_passed": validation_res.redteam_passed,
                "passed_tests": f"{validation_res.passed_redteam_tests}/{validation_res.total_redteam_tests}",
            },
            duration_ms=t_resolve,
        ))
        self.mulerun.emit_telemetry(
            "qoderwork_lifecycle",
            "resolved_completed",
            {"all_passed": all_passed, "redteam_passed": validation_res.redteam_passed},
        )

        total_duration = (time.time() - start_time) * 1000
        return QoderWorkLifecycleReport(
            workflow_id=wf_id,
            state="Resolved" if all_passed else "ActionRequired",
            steps=steps,
            findings_count=len(findings),
            patches_applied=applied_patches,
            redteam_passed=validation_res.redteam_passed,
            resolved=all_passed,
            total_time_ms=total_duration,
        )
