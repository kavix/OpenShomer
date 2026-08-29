import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["service"] == "OpenShomer"

def test_ingest_and_get_finding():
    payload = {
        "id": "SHOMER-001",
        "type": "OVER_PERMISSIONED_TOOL",
        "severity": "HIGH",
        "file": "agent/tools.yaml",
        "tool": "run_shell",
        "issue": "Shell tool has no human approval gate and unrestricted command scope",
        "repository": "customer-support-agent"
    }

    post_resp = client.post("/findings", json=payload)
    assert post_resp.status_code == 201
    receipt = post_resp.json()
    assert receipt["id"] == "SHOMER-001"
    assert receipt["status"] == "received"

    get_resp = client.get("/findings/SHOMER-001")
    assert get_resp.status_code == 200
    finding = get_resp.json()
    assert finding["id"] == "SHOMER-001"
    assert finding["type"] == "OVER_PERMISSIONED_TOOL"
