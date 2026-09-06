import re
import time
from typing import Any

from pydantic import BaseModel, Field

from app.frameworks.rag_security import RAGSecurityInspector


class FirewallInterception(BaseModel):
    action: str  # ALLOW, BLOCK, ESCALATE_HITL
    reason: str | None = None
    risk_score: float = 0.0
    latency_ms: float = 0.0
    timestamp: float = Field(default_factory=time.time)


class AIFirewallSidecar:
    """v0.5 Roadmap: Runtime AI Firewall & Observability Sidecar for live agent inference streams."""

    BLOCKED_SUBPROCESS_COMMANDS = [
        "rm -rf",
        "curl http://",
        "wget http://",
        "/etc/shadow",
        "mkfs",
        "dd if=",
        ":(){ :|:& };:",
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
            return FirewallInterception(
                action="BLOCK", reason="RATE_LIMIT_EXCEEDED", risk_score=1.0, latency_ms=latency
            )
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

    def intercept_retrieved_chunk(self, chunk_text: str, source_doc: str = "unknown") -> FirewallInterception:
        """Evaluates a retrieved RAG chunk before it is unpacked into the LLM context window."""
        start = time.perf_counter()
        inspector = RAGSecurityInspector()
        findings = inspector.inspect_retrieved_chunk(chunk_text, source_doc)

        # 1. Block high-severity context poisoning and credential leaks
        blocking = [f for f in findings if f.severity in ("HIGH", "CRITICAL")]
        if blocking:
            latency = (time.perf_counter() - start) * 1000
            return FirewallInterception(
                action="BLOCK",
                reason=f"DETECTED_CONTEXT_POISONING: {blocking[0].rule_id}",
                risk_score=1.0 if blocking[0].severity == "CRITICAL" else 0.9,
                latency_ms=latency,
            )

        # 2. Escalate medium-severity untrusted context (e.g. XSS payloads)
        if findings:
            latency = (time.perf_counter() - start) * 1000
            return FirewallInterception(
                action="ESCALATE_HITL",
                reason=f"DETECTED_UNTRUSTED_CONTEXT: {findings[0].rule_id}",
                risk_score=0.6,
                latency_ms=latency,
            )

        latency = (time.perf_counter() - start) * 1000
        return FirewallInterception(action="ALLOW", risk_score=0.0, latency_ms=latency)

    def sanitize_retrieved_chunk(self, chunk_text: str, source_doc: str = "unknown") -> str:
        """Redacts adversarial spans before the chunk is unpacked into the LLM context window."""
        inspector = RAGSecurityInspector()
        sanitized = chunk_text
        for pattern, _rule_id, _severity in inspector.SUSPICIOUS_CHUNK_PATTERNS:
            sanitized = re.sub(pattern, "[REDACTED_UNTRUSTED_CONTEXT]", sanitized, flags=re.IGNORECASE)
        return sanitized
