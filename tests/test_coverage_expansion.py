import json
from unittest.mock import MagicMock, patch

import pytest

from app.agents.providers import GeminiProvider, OpenAIProvider
from app.agents.tools import AgentRepoTools
from app.fast_io import FastEngineSerializer
from app.github.branches import BranchManager
from app.github.commits import CommitManager
from app.github.pull_requests import PullRequestManager
from app.models.findings import (
    Finding,
    FindingType,
    InvestigationResult,
    Severity,
    ValidationReport,
)
from app.models.industrial_reports import IndustrialReportExporter
from app.models.security_db import SecurityBenchmarkDatabase
from app.qoder.diff_synthesizer import DiffSynthesizer
from app.tui import OpenShomerTextualApp


def test_security_db_load_and_init(tmp_path):
    with patch.object(SecurityBenchmarkDatabase, "TAXONOMY_FILE", tmp_path / "tax.json"):
        data = SecurityBenchmarkDatabase.load_or_init()
        assert "standards" in data
        assert len(data["standards"]) == 4


def test_industrial_sarif_and_aibom_export(tmp_path):
    finding = Finding(
        id="SHOMER-001",
        type=FindingType.OVER_PERMISSIONED_TOOL,
        severity=Severity.HIGH,
        file="agent/tools.yaml",
        tool="run_shell",
        issue="Unrestricted shell execution",
        repository="test/repo"
    )
    sarif = IndustrialReportExporter.export_sarif([finding], tmp_path)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1

    aibom = IndustrialReportExporter.export_ai_bom(tmp_path, [finding])
    assert aibom["bomFormat"] == "CycloneDX"
    assert len(aibom["vulnerabilities"]) == 1


def test_pull_request_manager_taxonomy_and_mock_pr(tmp_path):
    tax = PullRequestManager.get_security_taxonomy_mapping("OVER_PERMISSIONED_TOOL")
    assert "LLM06" in tax["owasp"]
    tax_pi = PullRequestManager.get_security_taxonomy_mapping("PROMPT_INJECTION")
    assert "LLM01" in tax_pi["owasp"]
    tax_secret = PullRequestManager.get_security_taxonomy_mapping("HARDCODED_SECRET")
    assert "LLM02" in tax_secret["owasp"]
    tax_exfil = PullRequestManager.get_security_taxonomy_mapping("DATA_EXFILTRATION")
    assert "AML.T0044" in tax_exfil["mitre_atlas"]
    tax_other = PullRequestManager.get_security_taxonomy_mapping("OTHER_TYPE")
    assert "AML.TA0003" in tax_other["mitre_atlas"]

    finding = Finding(
        id="SHOMER-001",
        type=FindingType.OVER_PERMISSIONED_TOOL,
        severity=Severity.HIGH,
        file="agent/tools.yaml",
        issue="Unrestricted tool",
        repository="test/repo"
    )
    inv = InvestigationResult(
        finding_id="SHOMER-001",
        root_cause="Over-permissioned shell",
        recommended_fix="Add allow-lists",
        affected_files=["agent/tools.yaml"],
        confidence=0.95,
        risk=Severity.HIGH
    )
    val = ValidationReport(
        finding_id="SHOMER-001",
        static_checks_passed=True,
        permission_surface_reduced=True,
        redteam_passed=True,
        total_redteam_tests=10,
        passed_redteam_tests=10,
        status="passed",
        details=["Pass test 1"]
    )
    body = PullRequestManager.build_evidence_pr_body(finding, inv, val, "+ diff")
    assert "OWASP LLM Top 10" in body

    pr_mgr = PullRequestManager()
    url = pr_mgr.open_pr(finding, inv, val, "+ diff", token=None, repo_name="test/repo")
    assert "github.com/test/repo/pull/" in url


def test_branch_and_commit_managers():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="Success", stderr="")
        ok, msg = BranchManager.create_security_branch("test-branch", cwd=".")
        assert ok is True

        ok, msg = CommitManager.commit_patch(["file.txt"], "test commit", cwd=".")
        assert ok is True


def test_fast_io_edge_cases(tmp_path):
    data = {"key": "value", "number": 123}
    encoded = FastEngineSerializer.dumps(data)
    assert FastEngineSerializer.loads(encoded) == data

    raw_bytes = FastEngineSerializer.dumps_bytes(data)
    assert FastEngineSerializer.loads(raw_bytes) == data

    mp = FastEngineSerializer.dump_msgpack(data)
    assert FastEngineSerializer.load_msgpack(mp) == data

    bench_file = tmp_path / "bench.json"
    bench_file.write_text(json.dumps(data), encoding="utf-8")
    loaded = FastEngineSerializer.load_benchmark_suite(bench_file)
    assert loaded == data


def test_openai_and_gemini_providers():
    op = OpenAIProvider(api_key="dummy_key")
    with patch("httpx.Client.post") as mock_post:
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {"choices": [{"message": {"content": "OpenAI Response"}}]}
        mock_post.return_value = mock_resp
        res = op.generate("Test prompt")
        assert res == "OpenAI Response"

    gp = GeminiProvider(api_key="dummy_key")
    with patch("httpx.Client.post") as mock_post:
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {"candidates": [{"content": {"parts": [{"text": "Gemini Response"}]}}]}
        mock_post.return_value = mock_resp
        res = gp.generate("Test prompt")
        assert res == "Gemini Response"


def test_workspace_tools(tmp_path):
    tool_file = tmp_path / "agent/tools.yaml"
    tool_file.parent.mkdir(parents=True, exist_ok=True)
    tool_file.write_text("tools:\n  - name: test_tool\n", encoding="utf-8")

    prompt_file = tmp_path / "prompts/system.md"
    prompt_file.parent.mkdir(parents=True, exist_ok=True)
    prompt_file.write_text("System Prompt", encoding="utf-8")

    tools = AgentRepoTools(tmp_path)
    file_list = tools.list_files()
    assert len(file_list) >= 2
    assert tools.read_file("agent/tools.yaml") != ""
    assert len(tools.list_tools("agent/tools.yaml")) == 1
    assert tools.get_prompt_context("prompts/system.md")["length_chars"] > 0


def test_qoder_diff_synthesizer_edge_cases():
    orig_yaml = "tools:\n  - name: execute_sql\n    permissions: [db:all]\n"
    res, diff = DiffSynthesizer.synthesize_tool_yaml(orig_yaml)
    assert "db:read_only" in res

    orig_json = json.dumps({"mcpServers": {"filesystem": {"permissions": {"allowAllPaths": True}}}})
    res_j, diff_j = DiffSynthesizer.synthesize_mcp_json(orig_json)
    assert "allowAllPaths\": false" in res_j or "allowAllPaths\": False" in res_j.lower()


@pytest.mark.asyncio
async def test_tui_app_full_headless(tmp_path):
    app = OpenShomerTextualApp(workspace_root=tmp_path)
    async with app.run_test() as pilot:
        await pilot.pause()
        app.action_scan()
        await pilot.pause()
        app.action_mulerun()
        await pilot.pause()
        app.action_qoder()
        await pilot.pause()
        app.action_remediate()
        await pilot.pause()
        app.action_pr()
        await pilot.pause()
