from pathlib import Path
from app.models.findings import FindingType, Severity, InvestigationResult
from app.agents.remediation import RemediationEngine

def test_remediation_generates_safe_diff():
    workspace = Path("demo/vulnerable-agent")
    engine = RemediationEngine(workspace)

    investigation = InvestigationResult(
        finding_id="SHOMER-001",
        root_cause="run_shell tool lacks approval gate",
        affected_files=["agent/tools.yaml", "mcp/mcp_servers.json"],
        recommended_fix="Restrict tool commands and add approval gate",
        confidence=0.95,
        risk=Severity.HIGH
    )

    result = engine.remediate(investigation, FindingType.OVER_PERMISSIONED_TOOL)
    assert result.guardrails_passed is True
    assert "shell:restricted" in result.diff
    assert "requires_approval: true" in result.diff
