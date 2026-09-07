# Static LLM security rules

OpenShomer's deterministic checker reports structured findings for five OWASP LLM categories before an agent workspace is executed:

- **LLM01 — Direct prompt injection:** user-controlled placeholders must be inside an explicit untrusted-input boundary.
- **LLM02 — Sensitive information disclosure:** prompts must not contain credentials or instructions to reveal secrets and personal identifiers.
- **LLM06 — Excessive agency:** shell, subprocess, SQL, and unrestricted filesystem tools require approval or parameter bounds.
- **LLM07 — System prompt leakage:** system instructions must explicitly forbid disclosure of hidden instructions.
- **LLM08 — Vector and embedding weaknesses:** retrieval calls must enforce tenant filters and bounded result counts, and retrieved chunks must be inspected before prompt assembly.

The checker is intentionally conservative and deterministic. It reports findings for review; it does not claim that a prompt is safe merely because no pattern matched.

## LLM08 — Vector and Embedding Weaknesses

OpenShomer maps vector-query boundary failures to `LLM08_VECTOR_AND_EMBEDDING_WEAKNESS`. The scanner examines LangChain and LlamaIndex retrieval calls individually so one filtered retriever does not hide an unsafe call elsewhere in the same file.

| Rule ID | Severity | Detection heuristic | Required remediation |
|---|---|---|---|
| `MISSING_VECTOR_METADATA_FILTER` | High | A `VectorStoreRetriever`, `as_retriever`, `as_query_engine`, or `similarity_search` call has neither a `filter` nor `where` boundary. `MetadataFilters` and filter dictionaries are recognized. | Add a filter derived from trusted authentication context, such as `{"tenant_id": tenant_id}`, at every affected retrieval call. Never derive the tenant identifier from retrieved content or a model response. |
| `UNBOUNDED_VECTOR_TOP_K` | Medium | A literal `top_k`, `similarity_top_k`, keyword `k`, or `search_kwargs["k"]` value is greater than 50. | Reduce retrieval breadth to a bounded value. The automated synthesizer uses 10 and preserves an existing stricter bound. Apply reranking after tenant filtering when broader recall is necessary. |

### Query-boundary invariant

Every retrieval accepted into an agent's prompt must be scoped to the authenticated tenant before the vector store executes the query. The filter must survive framework adapters and nested query-engine configuration; a filter on one call does not authorize a sibling unfiltered call.

For LangChain, remediation adds `search_kwargs={"filter": {"tenant_id": tenant_id}, "k": 10}` to retrievers or `filter={"tenant_id": tenant_id}, k=10` to direct similarity searches. For LlamaIndex, it adds `vector_store_kwargs={"filter": {"tenant_id": tenant_id}}` and `similarity_top_k=10` to query engines and retrievers.

### Retrieved-content checks

Query isolation limits which records can be returned, but it does not make their contents trustworthy. Before prompt assembly, the RAG inspector also detects instruction overrides, system-role impersonation, executable-code payloads, XSS markers, and credential-like strings. High and critical findings must be blocked or sanitized; medium findings require review according to the calling application's policy.

See [Use Case 4](USE_CASES.md#use-case-4-multi-tenant-vector-store-isolation-and-context-poisoning-defense-uc-4) for vulnerable LangChain and LlamaIndex examples, the synthesized diff, and the end-to-end flow.
