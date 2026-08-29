from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class FindingType(str, Enum):
    OVER_PERMISSIONED_TOOL = "OVER_PERMISSIONED_TOOL"
    MISSING_APPROVAL_GATE = "MISSING_APPROVAL_GATE"
    PROMPT_INJECTION_SURFACE = "PROMPT_INJECTION_SURFACE"
    DATA_EXFILTRATION_PATH = "DATA_EXFILTRATION_PATH"
    HARDCODED_SECRET_IN_PROMPT = "HARDCODED_SECRET_IN_PROMPT"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingStatus(str, Enum):
    INGESTED = "INGESTED"
    INVESTIGATING = "INVESTIGATING"
    INVESTIGATED = "INVESTIGATED"
    REMEDIATING = "REMEDIATING"
    REMEDIATED = "REMEDIATED"
    VALIDATING = "VALIDATING"
    VALIDATED = "VALIDATED"
    PR_OPENED = "PR_OPENED"
    REJECTED = "REJECTED"
    NEEDS_HUMAN = "NEEDS_HUMAN"


class Finding(BaseModel):
    id: str = Field(..., description="Unique finding ID, e.g. SHOMER-001")
    type: FindingType = Field(..., description="Classification of the security risk")
    severity: Severity = Field(..., description="Severity level")
    file: str = Field(..., description="Relative path to affected config/prompt file")
    tool: Optional[str] = Field(None, description="Affected tool or MCP server name")
    issue: str = Field(..., description="Summary of the vulnerability")
    repository: str = Field(..., description="Repository or project name")
    status: FindingStatus = Field(default=FindingStatus.INGESTED, description="Current workflow status")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class FindingReceipt(BaseModel):
    status: str = "received"
    id: str
    type: FindingType
    severity: Severity
    message: str = "Finding queued for autonomous investigation and remediation"


class InvestigationResult(BaseModel):
    finding_id: str
    root_cause: str
    affected_files: List[str]
    recommended_fix: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    risk: Severity
    details: Optional[Dict[str, Any]] = Field(default_factory=dict)


class RemediationResult(BaseModel):
    finding_id: str
    diff: str
    modified_files: List[str]
    guardrails_passed: bool
    rejection_reason: Optional[str] = None


class ValidationReport(BaseModel):
    finding_id: str
    static_checks_passed: bool
    permission_surface_reduced: bool
    redteam_passed: bool
    total_redteam_tests: int
    passed_redteam_tests: int
    status: str
    details: List[str] = Field(default_factory=list)


class ResolutionResult(BaseModel):
    finding_id: str
    status: FindingStatus
    investigation: InvestigationResult
    remediation: RemediationResult
    validation: ValidationReport
    pr_url: Optional[str] = None
    evidence_summary: str
