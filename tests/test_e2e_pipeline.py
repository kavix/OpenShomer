from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

def test_e2e_resolution_flow():
    payload = {
        "id": "SHOMER-E2E-001",
        "type": "OVER_PERMISSIONED_TOOL",
        "severity": "HIGH",
        "file": "agent/tools.yaml",
        "tool": "run_shell",
        "issue": "Shell tool has unrestricted permissions",
        "repository": "customer-support-agent"
    }

    client.post("/findings", json=payload)
    res = client.post("/findings/SHOMER-E2E-001/resolve")
    assert res.status_code == 200
    data = res.json()
    assert data["finding_id"] == "SHOMER-E2E-001"
    assert data["investigation"]["root_cause"] != ""
    assert data["remediation"]["guardrails_passed"] is True
    assert "evidence_summary" in data
