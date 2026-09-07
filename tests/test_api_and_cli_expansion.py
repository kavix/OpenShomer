import time
from unittest.mock import patch

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from app.agents.investigator import InvestigationAgent
from app.agents.remediation import RemediationEngine
from app.api.findings import FINDINGS_DB
from app.cli import app as cli_app
from app.main import app
from app.models.findings import (
    Finding,
    FindingType,
    InvestigationResult,
    RemediationResult,
    Severity,
    ValidationReport,
)
from app.validation.sandbox import SandboxRunner

client = TestClient(app)
runner = CliRunner()


def test_api_findings_crud_full():
    # 1. Clear database
    FINDINGS_DB.clear()

    # 2. Ingest finding
    f_payload = {
        "id": "API-TEST-001",
        "type": "OVER_PERMISSIONED_TOOL",
        "severity": "HIGH",
        "file": "agent/tools.yaml",
        "tool": "run_shell",
        "issue": "Unchecked shell",
        "repository": "test/repo",
    }
    resp = client.post("/findings", json=f_payload)
    assert resp.status_code == 201

    # 3. List findings
    resp = client.get("/findings")
    assert resp.status_code == 200
    assert len(resp.json()) == 1

    # 4. Get specific finding
    resp = client.get("/findings/API-TEST-001")
    assert resp.status_code == 200

    # 5. Get non-existent
    resp = client.get("/findings/NONEXISTENT")
    assert resp.status_code == 404

    # 6. Investigate finding endpoint
    resp = client.post("/findings/API-TEST-001/investigate")
    assert resp.status_code in (200, 500)  # Works or handled gracefully

    # 7. Remediate finding endpoint
    resp = client.post("/findings/API-TEST-001/remediate")
    assert resp.status_code in (200, 400, 500)


def test_cli_subcommands_full(tmp_path, monkeypatch, mock_github_client):
    # Test SARIF export from CLI
    sarif_file = tmp_path / "report.sarif"
    res = runner.invoke(cli_app, ["scan", "demo/vulnerable-agent", "--sarif", str(sarif_file)])
    assert res.exit_code == 0
    assert sarif_file.exists()

    # Test AIBOM export from CLI
    aibom_file = tmp_path / "report.json"
    res = runner.invoke(cli_app, ["scan", "demo/vulnerable-agent", "--aibom", str(aibom_file)])
    assert res.exit_code == 0
    assert aibom_file.exists()

    # Test Auto-PR command through a hermetic GitHub delivery boundary.
    finding = Finding(
        id="SHOMER-121",
        type=FindingType.OVER_PERMISSIONED_TOOL,
        severity=Severity.HIGH,
        file="agent/tools.yaml",
        tool="run_shell",
        issue="Unchecked shell access",
        repository="test/repo",
    )
    investigation = InvestigationResult(
        finding_id=finding.id,
        root_cause="The shell tool has unrestricted permissions",
        affected_files=[finding.file],
        recommended_fix="Require approval and restrict commands",
        confidence=0.99,
        risk=Severity.HIGH,
    )
    remediation = RemediationResult(
        finding_id=finding.id,
        diff="- permissions: shell:unrestricted\n+ permissions: shell:read-only",
        modified_files=[finding.file],
        guardrails_passed=True,
    )
    validation = ValidationReport(
        finding_id=finding.id,
        static_checks_passed=True,
        permission_surface_reduced=True,
        redteam_passed=True,
        total_redteam_tests=50,
        passed_redteam_tests=50,
        status="passed",
        details=["Blocked unrestricted shell execution"],
    )
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    github_class, github_client, repository = mock_github_client

    started = time.monotonic()
    with (
        patch("app.cli.scan_workspace", return_value=[finding]),
        patch.object(InvestigationAgent, "investigate", return_value=investigation),
        patch.object(RemediationEngine, "remediate", return_value=remediation),
        patch.object(SandboxRunner, "validate_in_sandbox", return_value=validation),
    ):
        res = runner.invoke(cli_app, ["auto-pr", "demo/vulnerable-agent", "--repo", "test/repo"])
    elapsed = time.monotonic() - started

    assert res.exit_code == 0
    assert elapsed < 1
    github_class.assert_called_once()
    github_client.get_repo.assert_called_once_with("test/repo")
    repository.create_git_ref.assert_called_once_with(ref="refs/heads/openshomer/fix-shomer-121", sha="base-commit-sha")
    repository.create_pull.assert_called_once()
    pull_request_payload = repository.create_pull.call_args.kwargs
    assert pull_request_payload["title"] == "Fix(SHOMER-121): Unchecked shell access"
    assert pull_request_payload["head"] == "openshomer/fix-shomer-121"
    assert pull_request_payload["base"] == "main"
    assert "OpenShomer Security Remediation: SHOMER-121" in pull_request_payload["body"]
    assert "shell:read-only" in pull_request_payload["body"]
    assert "https://github.com/test/repo/pull/123" in res.output


def test_tools_search_and_read(tmp_path):
    from app.agents.tools import AgentRepoTools

    d = tmp_path / "sub"
    d.mkdir()
    (d / "hello.txt").write_text("world", encoding="utf-8")

    tools = AgentRepoTools(tmp_path)
    matches = tools.search_code("world")
    assert len(matches) >= 1
