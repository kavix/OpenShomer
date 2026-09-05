import time
from typing import Any
from pydantic import BaseModel, Field


class FirewallInterception(BaseModel):
    action: str  # ALLOW, BLOCK, ESCALATE_HITL
    reason: str | None = None
    risk_score: float = 0.0
    latency_ms: float = 0.0
    timestamp: float = Field(default_factory=time.time)


class AIFirewallSidecar:
    """v0.5 Roadmap: Runtime AI Firewall & Observability Sidecar for live agent inference streams."""

    BLOCKED_SUBPROCESS_COMMANDS = [
        "rm -rf", "curl http://", "wget http://", "/etc/shadow", "mkfs", "dd if=", ":(){ :|:& };:"
    ]

    def __init__(self, hitl_threshold: float = 0.7, max_qps: int = 30):
        self.hitl_threshold = hitl_threshold
        self.max_qps = max_qps
        self._call_history: list[float] = []

    def intercept_tool_call(self, tool_name: str, tool_args: dict[str, Any]) -> FirewallInterception:
        """Evaluates a pending tool execution before dispatching to runtime."""
        start = time.perf_counter()
        
        # 1. Rate Limiting
        now = time.time()
        self._call_history = [t for t in self._call_history if now - t < 1.0]
        if len(self._call_history) >= self.max_qps:
            latency = (time.perf_counter() - start) * 1000
            return FirewallInterception(action="BLOCK", reason="RATE_LIMIT_EXCEEDED", risk_score=1.0, latency_ms=latency)
        self._call_history.append(now)

        # 2. Inspect Arguments for Destructive Payloads
        args_str = str(tool_args).lower()
        for dangerous_cmd in self.BLOCKED_SUBPROCESS_COMMANDS:
            if dangerous_cmd in args_str:
                latency = (time.perf_counter() - start) * 1000
                return FirewallInterception(
                    action="BLOCK",
                    reason=f"DETECTED_MALICIOUS_PAYLOAD: {dangerous_cmd}",
                    risk_score=0.95,
                    latency_ms=latency,
                )

        # 3. Dynamic HITL Escalation for Privileged Operations
        high_privilege_keywords = ["shell", "delete", "drop", "grant", "refund", "execute_sql"]
        if any(kw in tool_name.lower() for kw in high_privilege_keywords):
            latency = (time.perf_counter() - start) * 1000
            return FirewallInterception(
                action="ESCALATE_HITL",
                reason=f"PRIVILEGED_TOOL_INVOCATION: {tool_name} requires human authorization token",
                risk_score=0.75,
                latency_ms=latency,
            )

        latency = (time.perf_counter() - start) * 1000
        return FirewallInterception(action="ALLOW", risk_score=0.0, latency_ms=latency)
