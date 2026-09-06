import re
from typing import Any

from pydantic import BaseModel, Field

from app.models.findings import Finding, FindingType, Severity


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
        (
            r"(?:api_key|secret_key|private_key)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
            "CREDENTIAL_LEAK_IN_EMBEDDINGS",
            "CRITICAL",
        ),
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

    def extract_query_config_from_source(self, source: str) -> dict[str, Any]:
        """Best-effort parse of filter/where and top_k/k from Python retrieval call sites."""
        config: dict[str, Any] = {}

        # 1. Tenant metadata filter (filter=, where=, MetadataFilters, or dict keys)
        has_filter = bool(
            re.search(r"(?:filter|where)\s*=", source)
            or "MetadataFilters" in source
            or re.search(r"['\"](?:filter|where)['\"]\s*:", source)
        )
        if has_filter:
            config["filter"] = {"present": True}

        # 2. Retrieval breadth (similarity_top_k, top_k, or search_kwargs k)
        k_match = re.search(r"(?:similarity_top_k|top_k)\s*=\s*(\d+)", source)
        dict_k = re.search(r"['\"]k['\"]\s*:\s*(\d+)", source)
        kw_k = re.search(r"(?<![A-Za-z0-9_])k\s*=\s*(\d+)", source)
        if k_match:
            config["top_k"] = int(k_match.group(1))
        elif dict_k:
            config["top_k"] = int(dict_k.group(1))
        elif kw_k:
            config["top_k"] = int(kw_k.group(1))

        return config

    def _iter_call_args(self, source: str, func_name: str) -> list[str]:
        """Collect argument snippets for each func_name( call using balanced parentheses."""
        args_list: list[str] = []
        for match in re.finditer(rf"(?<![A-Za-z0-9_]){re.escape(func_name)}\s*\(", source):
            open_idx = match.end() - 1
            depth = 0
            for i in range(open_idx, len(source)):
                if source[i] == "(":
                    depth += 1
                elif source[i] == ")":
                    depth -= 1
                    if depth == 0:
                        args_list.append(source[open_idx + 1 : i])
                        break
        return args_list

    def inspect_python_retrieval_source(self, source: str) -> list[RAGSecurityFinding]:
        """Inspects each LangChain/LlamaIndex retrieval call for missing filters and unbounded top_k."""
        call_args: list[str] = []
        for func_name in ("as_retriever", "as_query_engine", "similarity_search", "VectorStoreRetriever"):
            call_args.extend(self._iter_call_args(source, func_name))
        snippets = call_args or [source]
        merged: list[RAGSecurityFinding] = []
        seen: set[str] = set()
        for snippet in snippets:
            for finding in self.inspect_vector_query_config(self.extract_query_config_from_source(snippet)):
                if finding.rule_id not in seen:
                    seen.add(finding.rule_id)
                    merged.append(finding)
        return merged

    def to_pipeline_finding(
        self,
        rag_finding: RAGSecurityFinding,
        *,
        file: str,
        finding_id: str,
        repository: str,
    ) -> Finding:
        """Bridges runtime RAG rule hits onto the scan/fix Finding pipeline."""
        return Finding(
            id=finding_id,
            type=FindingType.VECTOR_AND_EMBEDDING_WEAKNESS,
            severity=Severity(rag_finding.severity),
            file=file,
            issue=f"{rag_finding.rule_id}: {rag_finding.issue}",
            repository=repository,
            metadata={"rule_id": rag_finding.rule_id, **rag_finding.metadata},
        )
