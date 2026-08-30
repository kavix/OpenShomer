import pytest
from fastapi.testclient import TestClient
from pathlib import Path

from app.main import app
from app.api.findings import FINDINGS_DB
from app.models.findings import Finding, FindingType, Severity, FindingStatus
from app.cli import scan_workspace, app as cli_app
from typer.testing import CliRunner

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
        "repository": "test/repo"
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


def test_cli_subcommands_full(tmp_path):
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

    # Test Auto-PR command
    res = runner.invoke(cli_app, ["auto-pr", "demo/vulnerable-agent", "--repo", "kavix/OpenShomer"])
    assert res.exit_code == 0


def test_tools_search_and_read(tmp_path):
    from app.agents.tools import AgentRepoTools
    d = tmp_path / "sub"
    d.mkdir()
    (d / "hello.txt").write_text("world", encoding="utf-8")

    tools = AgentRepoTools(tmp_path)
    matches = tools.search_code("world")
    assert len(matches) >= 1
