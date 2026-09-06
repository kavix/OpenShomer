# OpenShomer — Progress & Release Update

**Releases:** [v0.1.0](https://github.com/kavix/OpenShomer/releases/tag/v0.1.0) & [v0.2.0](https://github.com/kavix/OpenShomer/releases/tag/v0.2.0)
**Author:** @kavix

---

## TL;DR

> OpenShomer **v0.1 (Core Loop MVP)**, **v0.2 (Richer Agent Graphs)**, and **v0.4 (RAG & Vector Store Security Pipeline)** are complete, tested (78 passing tests), built, and merged. PR #104 officially completes and closes Issue #100. OpenShomer features the **MuleRun** AI workflow runtime, the **QoderWork** autonomous desktop security agent, the **Qoder** AI-native diff synthesizer, full multi-framework support for **LangChain**, **LlamaIndex**, **CrewAI**, **Agent Skill Files**, and end-to-end RAG context poisoning & tenant isolation defenses.

---

## Current Project Status

OpenShomer is an autonomous AI-agent security engineer that closes the remediation loop: **Find → Investigate → Rewrite → Red-team → Prove → PR**.

### Completed Milestones

#### ✅ v0.1 — Core Loop (MVP) & Agentic Backbone
* **Finding Ingestion API**: FastAPI control plane with `Finding` schema and Docker containerization.
* **Investigation Agent**: LLM graph inspection loop with read-only repository tools producing structured `InvestigationResult`.
* **Remediation Engine + Patch Guardrails**: Minimal safe rewrites with scope, size, permission reduction, and syntax validation.
* **Validation Sandbox + Adversarial Red-Teaming**: 156-case adversarial red-team suite covering prompt injection and tool abuse.
* **GitHub PR Automation**: Branch, commit, and evidence-backed PR generation with before/after security proof.
* **MuleRun AI Workflow Runtime**: Automated event orchestrator, GitHub HMAC-SHA256 webhook ingress, Alibaba Cloud Qwen reasoning gateway, and live sandbox telemetry streaming.
* **QoderWork Desktop AI Agent**: Autonomous 4-stage lifecycle (`Trigger` → `Investigate` → `Action` → `Resolved`).
* **Qoder Agentic IDE Backbone**: Precision AST/schema-aware diff synthesizer and defensive prompt fences.

#### ✅ v0.2 — Richer Agent Graphs & Framework Support
* **Skill Files Framework**: Security auditing and bash command fencing for `SKILL.md` and `skills/**` configurations.
* **LangChain Agents**: Unbounded subshell `Tool` detection and `AgentExecutor` runaway execution protection.
* **LlamaIndex Agents**: Dangerous `FunctionTool` primitive validation and `ReActAgent` safeguards.
* **CrewAI Multi-Agent Delegation**: Scoping unconstrained multi-agent delegation (`allow_delegation=True`) paired with privileged tool execution.

#### ✅ v0.4 — RAG & Vector Store Security Pipeline (PR #104, Closes Issue #100)
* **Vector Retrieval AST Inspection**: Scans LangChain `VectorStoreRetriever` and LlamaIndex `VectorStoreIndex` retrieval queries for missing tenant isolation filters and unbounded `top_k` retrieval parameters (`MISSING_VECTOR_METADATA_FILTER`).
* **Automated Safe AST Remediation**: Synthesizes Python AST diffs via Qoder that inject parameterized `{"tenant_id": tenant_id}` metadata filter dictionaries and enforce bounded query limits (`k <= 50`).
* **Context Poisoning & Indirect Injection Defense**: `RAGSecurityInspector` inspects ingested and retrieved chunks against indirect prompt injection, role spoofing, executable script injection, and canary credential leaks.
* **Runtime AI Firewall Sanitization**: Intercepts and cleans poisoned context chunks in-flight before ingestion into the LLM context window (`app/runtime/firewall.py`).

---

### In Active Development (Foundational Prototypes)

#### 🟡 v0.3 — Advanced Red-Teaming & Tool-Chaining Exploit Detection
* **Multi-Turn Crescendo Simulator (`app/redteam/multiturn.py`)**: Scenario progression engine covering privilege escalation and role hypnosis. Adaptive conversational attacker loop in progress ([Issue #99](https://github.com/kavix/OpenShomer/issues/99)).
* **Tool-Chaining Taint Detection (`app/redteam/multiturn.py`)**: Pattern matching for unsafe source-to-sink tool calls. Dynamic execution DAG taint-tracking in progress.

#### 🟡 v0.5 — Runtime Observability & Live AI Firewall
* **AI Firewall Sidecar (`app/runtime/firewall.py`)**: Rate-limiting and destructive payload inspection implemented. Real-time token streaming reverse proxy sidecar in development ([Issue #101](https://github.com/kavix/OpenShomer/issues/101)).
* **Cryptographic HITL Gate Provider (`app/hitl/gates.py`)**: HMAC request signing and verification foundation implemented. Hardening parameter/decision binding and Slack/Discord webhook delivery underway ([Issue #102](https://github.com/kavix/OpenShomer/issues/102)).

---

### Planned Milestones (Not Yet Implemented)

* ⏳ **v0.6 — IDE Integration**: VS Code & JetBrains extension for real-time prompt and permission linting ([Issue #103](https://github.com/kavix/OpenShomer/issues/103)).
* ⏳ **PyPI & Container Registry Distribution**: Automated publishing for `openshomer` CLI on PyPI and Docker Hub / GHCR ([Issue #28](https://github.com/kavix/OpenShomer/issues/28)).
* ⏳ **Interactive Evidence Web Dashboard**: Standalone dashboard visualizing remediation AST diffs and execution traces ([Issue #23](https://github.com/kavix/OpenShomer/issues/23)).

---

## Verification & Releases
* **Test Suite**: 78/78 unit, integration, and framework tests passing.
* **Pull Request #104**: [PR #104: feat(v0.4): complete RAG vector store security pipeline](https://github.com/kavix/OpenShomer/pull/104) merged into `main`, closing [Issue #100](https://github.com/kavix/OpenShomer/issues/100).
* **Release v0.1.0**: [GitHub Release v0.1.0](https://github.com/kavix/OpenShomer/releases/tag/v0.1.0)
* **Release v0.2.0**: [GitHub Release v0.2.0](https://github.com/kavix/OpenShomer/releases/tag/v0.2.0)
