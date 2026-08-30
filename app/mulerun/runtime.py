import time
import uuid
from typing import Dict, Any, List, Optional, Callable
from pydantic import BaseModel, Field
from app.agents.providers import LLMProvider, get_llm_provider, AlibabaQwenProvider


class TelemetryEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = Field(default_factory=time.time)
    stage: str
    event_type: str
    data: Dict[str, Any] = Field(default_factory=dict)
    duration_ms: float = 0.0


class MuleRunResult(BaseModel):
    workflow_id: str
    status: str
    execution_time_ms: float
    telemetry: List[TelemetryEvent] = Field(default_factory=list)
    output: Dict[str, Any] = Field(default_factory=dict)
    success: bool = True


class MuleRunRuntime:
    """MuleRun: Low-latency (<100 ms) AI Workflow Runtime.
    
    Orchestrates automated security workflows, connects Alibaba Cloud Qwen reasoning
    models, GitHub repository webhooks, and sandbox execution telemetry into a unified runtime.
    """

    def __init__(self, llm_provider: Optional[LLMProvider] = None):
        self.llm_provider = llm_provider or get_llm_provider()
        self.telemetry_history: List[TelemetryEvent] = []
        self._subscribers: List[Callable[[TelemetryEvent], None]] = []

    def subscribe_telemetry(self, callback: Callable[[TelemetryEvent], None]) -> None:
        """Register a real-time telemetry stream listener."""
        self._subscribers.append(callback)

    def emit_telemetry(self, stage: str, event_type: str, data: Optional[Dict[str, Any]] = None, duration_ms: float = 0.0) -> TelemetryEvent:
        """Emit telemetry event to all subscribers and append to history."""
        event = TelemetryEvent(
            stage=stage,
            event_type=event_type,
            data=data or {},
            duration_ms=duration_ms,
        )
        self.telemetry_history.append(event)
        for sub in self._subscribers:
            try:
                sub(event)
            except Exception:
                pass
        return event

    def process_webhook_event(self, webhook_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Ingest and normalize a GitHub repository webhook event in < 50ms."""
        start_time = time.time()
        event_name = webhook_payload.get("event", "push")
        repo = webhook_payload.get("repository", {}).get("full_name", "unknown/repo")
        ref = webhook_payload.get("ref", "refs/heads/main")
        commits = webhook_payload.get("commits", [])
        
        modified_files = set()
        for c in commits:
            for f in c.get("modified", []) + c.get("added", []):
                modified_files.add(f)

        duration_ms = (time.time() - start_time) * 1000
        self.emit_telemetry(
            stage="webhook_ingestion",
            event_type="github_webhook_received",
            data={
                "event": event_name,
                "repository": repo,
                "ref": ref,
                "modified_files": list(modified_files),
            },
            duration_ms=duration_ms,
        )

        return {
            "event": event_name,
            "repository": repo,
            "ref": ref,
            "affected_files": list(modified_files),
            "latency_ms": duration_ms,
        }

    def execute_workflow(
        self,
        workflow_name: str,
        steps: List[Callable[..., Any]],
        context: Optional[Dict[str, Any]] = None,
    ) -> MuleRunResult:
        """Execute a low-latency sequential security workflow with live telemetry."""
        wf_id = f"wf-{uuid.uuid4().hex[:8]}"
        start_time = time.time()
        ctx = context or {}
        telemetry: List[TelemetryEvent] = []

        self.emit_telemetry(
            stage="workflow_start",
            event_type="workflow_initialized",
            data={"workflow_id": wf_id, "workflow_name": workflow_name},
        )

        success = True
        for idx, step in enumerate(steps):
            step_start = time.time()
            step_name = getattr(step, "__name__", f"step_{idx}")
            try:
                result = step(ctx)
                step_duration = (time.time() - step_start) * 1000
                evt = self.emit_telemetry(
                    stage=f"step_{idx}_{step_name}",
                    event_type="step_completed",
                    data={"result_type": type(result).__name__},
                    duration_ms=step_duration,
                )
                telemetry.append(evt)
                if isinstance(result, dict):
                    ctx.update(result)
            except Exception as e:
                step_duration = (time.time() - step_start) * 1000
                evt = self.emit_telemetry(
                    stage=f"step_{idx}_{step_name}",
                    event_type="step_failed",
                    data={"error": str(e)},
                    duration_ms=step_duration,
                )
                telemetry.append(evt)
                success = False
                break

        total_time_ms = (time.time() - start_time) * 1000
        return MuleRunResult(
            workflow_id=wf_id,
            status="success" if success else "failed",
            execution_time_ms=total_time_ms,
            telemetry=telemetry,
            output=ctx,
            success=success,
        )
