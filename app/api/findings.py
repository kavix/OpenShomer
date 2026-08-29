from fastapi import APIRouter, HTTPException, status
from pathlib import Path
from typing import Dict, List
import os

from app.models.findings import (
    Finding,
    FindingStatus,
    FindingReceipt,
    InvestigationResult,
    RemediationResult,
    ValidationReport,
    ResolutionResult
)
from app.agents.investigator import InvestigationAgent
from app.agents.remediation import RemediationEngine
from app.validation.sandbox import SandboxRunner
from app.github.pull_requests import PullRequestManager

router = APIRouter(prefix="/findings", tags=["findings"])

# In-memory findings database for MVP
FINDINGS_DB: Dict[str, Finding] = {}
INVESTIGATIONS_DB: Dict[str, InvestigationResult] = {}
REMEDIATIONS_DB: Dict[str, RemediationResult] = {}
VALIDATIONS_DB: Dict[str, ValidationReport] = {}

def get_workspace_root() -> Path:
    # Default to demo fixture if in test or workspace root
    base = Path(os.environ.get("OPENSHOMER_WORKSPACE", "demo/vulnerable-agent"))
    return base if base.exists() else Path(".")

def get_redteam_dir() -> Path:
    return Path("redteam")


@router.post("", response_model=FindingReceipt, status_code=status.HTTP_201_CREATED)
def ingest_finding(finding: Finding) -> FindingReceipt:
    """Ingest a new security finding for automated processing."""
    FINDINGS_DB[finding.id] = finding
    return FindingReceipt(
        status="received",
        id=finding.id,
        type=finding.type,
        severity=finding.severity,
        message="Finding queued for autonomous investigation and remediation"
    )


@router.get("", response_model=List[Finding])
def list_findings() -> List[Finding]:
    """List all ingested findings."""
    return list(FINDINGS_DB.values())


@router.get("/{finding_id}", response_model=Finding)
def get_finding(finding_id: str) -> Finding:
    """Retrieve finding by ID."""
    if finding_id not in FINDINGS_DB:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")
    return FINDINGS_DB[finding_id]


@router.post("/{finding_id}/investigate", response_model=InvestigationResult)
def investigate_finding(finding_id: str) -> InvestigationResult:
    """Run Phase 2 Investigation on a finding."""
    if finding_id not in FINDINGS_DB:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")
    
    finding = FINDINGS_DB[finding_id]
    finding.status = FindingStatus.INVESTIGATING

    investigator = InvestigationAgent(get_workspace_root())
    result = investigator.investigate(finding)

    INVESTIGATIONS_DB[finding_id] = result
    finding.status = FindingStatus.INVESTIGATED
    return result


@router.post("/{finding_id}/remediate", response_model=RemediationResult)
def remediate_finding(finding_id: str) -> RemediationResult:
    """Run Phase 3 Remediation & Guardrails on a finding."""
    if finding_id not in FINDINGS_DB:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")
    
    finding = FINDINGS_DB[finding_id]
    investigation = INVESTIGATIONS_DB.get(finding_id)
    if not investigation:
        investigator = InvestigationAgent(get_workspace_root())
        investigation = investigator.investigate(finding)
        INVESTIGATIONS_DB[finding_id] = investigation

    finding.status = FindingStatus.REMEDIATING
    engine = RemediationEngine(get_workspace_root())
    remediation = engine.remediate(investigation, finding.type)

    REMEDIATIONS_DB[finding_id] = remediation
    finding.status = FindingStatus.REMEDIATED if remediation.guardrails_passed else FindingStatus.NEEDS_HUMAN
    return remediation


@router.post("/{finding_id}/validate", response_model=ValidationReport)
def validate_finding(finding_id: str) -> ValidationReport:
    """Run Phase 4 Sandbox & Red-Teaming on a finding."""
    if finding_id not in FINDINGS_DB:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")
    
    finding = FINDINGS_DB[finding_id]
    remediation = REMEDIATIONS_DB.get(finding_id)
    diff = remediation.diff if remediation else ""

    finding.status = FindingStatus.VALIDATING
    sandbox = SandboxRunner(get_redteam_dir())
    report = sandbox.validate_in_sandbox(get_workspace_root(), finding_id, diff)

    VALIDATIONS_DB[finding_id] = report
    finding.status = FindingStatus.VALIDATED if report.redteam_passed else FindingStatus.REJECTED
    return report


@router.post("/{finding_id}/resolve", response_model=ResolutionResult)
def resolve_finding_e2e(finding_id: str) -> ResolutionResult:
    """Execute complete workflow: Ingest -> Investigate -> Remediate -> Sandbox Red-Team -> PR."""
    if finding_id not in FINDINGS_DB:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")
    
    finding = FINDINGS_DB[finding_id]
    ws = get_workspace_root()
    rt_dir = get_redteam_dir()

    # 1. Investigate
    investigator = InvestigationAgent(ws)
    investigation = investigator.investigate(finding)
    INVESTIGATIONS_DB[finding_id] = investigation

    # 2. Remediate
    engine = RemediationEngine(ws)
    remediation = engine.remediate(investigation, finding.type)
    REMEDIATIONS_DB[finding_id] = remediation

    # 3. Sandbox Red-Team Validation
    sandbox = SandboxRunner(rt_dir)
    validation = sandbox.validate_in_sandbox(ws, finding_id, remediation.diff)
    VALIDATIONS_DB[finding_id] = validation

    # 4. Open PR
    pr_manager = PullRequestManager()
    pr_url = None
    if validation.redteam_passed:
        pr_url = pr_manager.open_pr(finding, investigation, validation, remediation.diff)
        finding.status = FindingStatus.PR_OPENED
    else:
        finding.status = FindingStatus.REJECTED

    evidence_summary = (
        f"Verified with {validation.passed_redteam_tests}/{validation.total_redteam_tests} passing red-team tests. "
        f"Result: {validation.status}"
    )

    return ResolutionResult(
        finding_id=finding_id,
        status=finding.status,
        investigation=investigation,
        remediation=remediation,
        validation=validation,
        pr_url=pr_url,
        evidence_summary=evidence_summary
    )
