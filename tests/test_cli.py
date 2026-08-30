import json
from pathlib import Path
import pytest
from typer.testing import CliRunner
from app.cli import app

runner = CliRunner()


def test_cli_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "OpenShomer" in result.stdout
    assert "scan" in result.stdout
    assert "version" in result.stdout


def test_cli_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "OpenShomer CLI v0.1.0" in result.stdout


def test_cli_scan_nonexistent_directory():
    result = runner.invoke(app, ["scan", "nonexistent/directory/path"])
    assert result.exit_code == 2
    assert "not exist" in result.stdout or "Error" in result.stdout


def test_cli_scan_clean_workspace(tmp_path):
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "Zero security risks found" in result.stdout


def test_cli_scan_demo_vulnerable_agent_exit_code():
    result = runner.invoke(app, ["scan", "demo/vulnerable-agent"])
    assert result.exit_code == 1
    assert "security risk(s) found" in result.stdout
    assert "SHOMER-001" in result.stdout
    assert "agent/tools.yaml" in result.stdout


def test_cli_scan_demo_vulnerable_agent_no_exit_code():
    result = runner.invoke(app, ["scan", "demo/vulnerable-agent", "--no-exit-code"])
    assert result.exit_code == 0
    assert "security risk(s) found" in result.stdout


def test_cli_scan_json_output():
    result = runner.invoke(app, ["scan", "demo/vulnerable-agent", "--json", "--no-exit-code"])
    assert result.exit_code == 0
    findings = json.loads(result.stdout)
    assert isinstance(findings, list)
    assert len(findings) >= 2
    finding_types = {f["type"] for f in findings}
    assert "OVER_PERMISSIONED_TOOL" in finding_types
    assert any(f["file"] == "agent/tools.yaml" for f in findings)
    assert any(f["tool"] == "run_shell" for f in findings)
