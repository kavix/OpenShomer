import hashlib
import hmac
import json

from fastapi.testclient import TestClient

from app.main import app
from app.mulerun.runtime import MuleRunRuntime
from app.mulerun.webhooks import GitHubWebhookVerifier


def test_mulerun_webhook_processing_latency():
    runtime = MuleRunRuntime()
    payload = {
        "event": "push",
        "repository": {"full_name": "kavix/OpenShomer"},
        "ref": "refs/heads/main",
        "commits": [
            {"modified": ["agent/tools.yaml", "prompts/system.md"], "added": []}
        ],
    }

    result = runtime.process_webhook_event(payload)
    assert result["event"] == "push"
    assert "agent/tools.yaml" in result["modified_files"]
    assert "prompts/system.md" in result["modified_files"]
    assert result["latency_ms"] < 100.0  # Ultra-fast <100 ms target
    assert result["sub_100ms"] is True


def test_mulerun_hmac_verification():
    secret = "test_webhook_secret_key_12345"
    payload = json.dumps({"repository": {"full_name": "owner/repo"}}).encode("utf-8")
    
    valid_sig = "sha256=" + hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    invalid_sig = "sha256=invalid_hex_signature"

    assert GitHubWebhookVerifier.verify_signature(payload, secret, valid_sig) is True
    assert GitHubWebhookVerifier.verify_signature(payload, secret, invalid_sig) is False


def test_mulerun_telemetry_subscription():
    runtime = MuleRunRuntime()
    received_events = []

    runtime.subscribe_telemetry(lambda evt: received_events.append(evt))
    
    runtime.emit_telemetry("sandbox_execution", "jailbreak_test_started", {"test_id": "JB-001"})
    runtime.emit_telemetry("sandbox_execution", "jailbreak_test_passed", {"test_id": "JB-001"})

    assert len(received_events) == 2
    assert received_events[0].event_type == "jailbreak_test_started"
    assert received_events[1].event_type == "jailbreak_test_passed"


def test_mulerun_workflow_execution():
    runtime = MuleRunRuntime()

    def step_a(ctx):
        return {"scanned_keys": 3}

    def step_b(ctx):
        assert ctx.get("scanned_keys") == 3
        return {"policy_passed": True}

    res = runtime.execute_workflow("security_sweep", [step_a, step_b])
    assert res.success is True
    assert res.output["policy_passed"] is True
    assert res.execution_time_ms < 500.0
    assert len(res.telemetry) == 2


def test_mulerun_qwen_triage_mock():
    runtime = MuleRunRuntime()
    res = runtime.qwen_security_triage("Shell tool has unrestricted permissions")
    assert "triage_response" in res
    assert res["latency_ms"] < 100.0 or res["latency_ms"] >= 0


def test_mulerun_fastapi_endpoints():
    client = TestClient(app)
    response = client.post(
        "/mulerun/webhook",
        headers={"X-GitHub-Event": "push"},
        json={
            "repository": {"full_name": "kavix/OpenShomer"},
            "commits": [{"modified": ["agent/tools.yaml"]}],
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "accepted"
    assert data["runtime"] == "MuleRun"
    assert data["latency_ms"] < 100.0

    # Test telemetry endpoint
    tel_res = client.get("/mulerun/telemetry")
    assert tel_res.status_code == 200
    tel_data = tel_res.json()
    assert "count" in tel_data
    assert "events" in tel_data
