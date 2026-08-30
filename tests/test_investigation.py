from pathlib import Path

from app.agents.investigator import InvestigationAgent
from app.models.findings import Finding, FindingType, Severity


def test_investigator_diagnoses_over_permissioned_tool():
    workspace = Path("demo/vulnerable-agent")
    investigator = InvestigationAgent(workspace)

    finding = Finding(
        id="SHOMER-001",
        type=FindingType.OVER_PERMISSIONED_TOOL,
        severity=Severity.HIGH,
        file="agent/tools.yaml",
        tool="run_shell",
        issue="Unrestricted shell execution",
        repository="customer-support-agent"
    )

    result = investigator.investigate(finding)
    assert result.finding_id == "SHOMER-001"
    assert "run_shell" in result.root_cause
    assert "agent/tools.yaml" in result.affected_files
    assert result.confidence >= 0.9
