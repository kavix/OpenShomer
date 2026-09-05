import re
from typing import Any
from pydantic import BaseModel, Field


class RAGSecurityFinding(BaseModel):
    rule_id: str
    severity: str
    component: str
    issue: str
    recommendation: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class RAGSecurityInspector:
    """v0.4 Roadmap: Security inspector for RAG retrieval pipelines and Vector Stores."""

    SUSPICIOUS_CHUNK_PATTERNS = [
        (r"ignore\s+(?:all\s+)?previous\s+instructions", "PROMPT_INJECTION_IN_RETRIEVAL", "HIGH"),
        (r"system\s*:\s*you\s+are\s+now", "SYSTEM_ROLE_IMPERSONATION_IN_CHUNK", "CRITICAL"),
        (r"eval\(|exec\(|subprocess\.Popen", "CODE_EXECUTION_PAYLOAD_IN_CHUNK", "HIGH"),
        (r"<script[\s>]|javascript:", "XSS_PAYLOAD_IN_CONTEXT", "MEDIUM"),
        (r"(?:api_key|secret_key|private_key)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "CREDENTIAL_LEAK_IN_EMBEDDINGS", "CRITICAL"),
    ]

    def inspect_retrieved_chunk(self, chunk_text: str, source_doc: str = "unknown") -> list[RAGSecurityFinding]:
        """Inspects retrieved context chunks for indirect prompt injection or context poisoning."""
        findings: list[RAGSecurityFinding] = []
        for pattern, rule_id, severity in self.SUSPICIOUS_CHUNK_PATTERNS:
            if re.search(pattern, chunk_text, re.IGNORECASE):
                findings.append(
                    RAGSecurityFinding(
                        rule_id=rule_id,
                        severity=severity,
                        component=f"RAGContextChunk ({source_doc})",
                        issue=f"Detected adversarial pattern in retrieved chunk: {rule_id}",
                        recommendation="Enforce chunk sanitization, semantic boundary fencing, and source isolation.",
                        metadata={"source": source_doc, "sample": chunk_text[:120]},
                    )
                )
        return findings

    def inspect_vector_query_config(self, query_config: dict[str, Any]) -> list[RAGSecurityFinding]:
        """Validates vector store query parameters for tenant isolation and bounding."""
        findings: list[RAGSecurityFinding] = []
        
        # 1. Missing tenant/user metadata filter (Multi-tenant data bleed)
        metadata_filters = query_config.get("filter") or query_config.get("where")
        if not metadata_filters:
            findings.append(
                RAGSecurityFinding(
                    rule_id="MISSING_VECTOR_METADATA_FILTER",
                    severity="HIGH",
                    component="VectorStoreQuery",
                    issue="Vector retrieval query executed without metadata tenant isolation filter.",
                    recommendation="Attach mandatory user_id/organization_id metadata filters to prevent cross-tenant data leakage.",
                )
            )

        # 2. Unbounded top_k retrieval (Context window flooding / DoS)
        top_k = query_config.get("top_k", 4)
        if isinstance(top_k, int) and top_k > 50:
            findings.append(
                RAGSecurityFinding(
                    rule_id="UNBOUNDED_VECTOR_TOP_K",
                    severity="MEDIUM",
                    component="VectorStoreQuery",
                    issue=f"Excessive top_k parameter ({top_k}) poses context flooding and token exhaustion risk.",
                    recommendation="Limit top_k to <= 20 and apply reranking.",
                    metadata={"top_k": top_k},
                )
            )

        return findings
