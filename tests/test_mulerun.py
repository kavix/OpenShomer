import time
from app.mulerun.runtime import MuleRunRuntime, TelemetryEvent


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
    assert "agent/tools.yaml" in result["affected_files"]
    assert "prompts/system.md" in result["affected_files"]
    assert result["latency_ms"] < 100.0  # Ultra-fast <100 ms target


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
