import hashlib
import hmac
import time
from typing import Any
from pydantic import BaseModel, Field


class ApprovalRequest(BaseModel):
    request_id: str
    tool_name: str
    parameters: dict[str, Any]
    risk_level: str
    created_at: float = Field(default_factory=time.time)
    signature: str


class HITLGateManager:
    """Enterprise Human-in-the-Loop (HITL) gate provider for high-risk autonomous agent operations."""

    def __init__(self, secret_key: str = "openshomer_hitl_secret_key_default"):
        self.secret_key = secret_key.encode("utf-8")
        self._pending_approvals: dict[str, ApprovalRequest] = {}
        self._resolved_approvals: dict[str, bool] = {}

    def generate_approval_request(self, tool_name: str, parameters: dict[str, Any], risk_level: str = "HIGH") -> ApprovalRequest:
        """Creates a signed approval request for a sensitive tool operation."""
        req_id = hashlib.sha256(f"{tool_name}:{time.time()}:{parameters}".encode()).hexdigest()[:16]
        payload = f"{req_id}:{tool_name}:{risk_level}".encode("utf-8")
        sig = hmac.new(self.secret_key, payload, hashlib.sha256).hexdigest()

        req = ApprovalRequest(
            request_id=req_id,
            tool_name=tool_name,
            parameters=parameters,
            risk_level=risk_level,
            signature=sig,
        )
        self._pending_approvals[req_id] = req
        return req

    def verify_and_resolve(self, request_id: str, signature: str, approved: bool) -> bool:
        """Validates approval HMAC signature and records resolution."""
        if request_id not in self._pending_approvals:
            return False

        req = self._pending_approvals[request_id]
        payload = f"{request_id}:{req.tool_name}:{req.risk_level}".encode("utf-8")
        expected_sig = hmac.new(self.secret_key, payload, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(sig_to_check := signature, expected_sig):
            return False

        self._resolved_approvals[request_id] = approved
        del self._pending_approvals[request_id]
        return True

    def is_operation_approved(self, request_id: str) -> bool:
        """Checks if a previously submitted request has been formally approved."""
        return self._resolved_approvals.get(request_id, False)
