# OpenShomer — Project Roadmap & Implementation Matrix

This document maintains the canonical implementation status for OpenShomer, delineating between **fully implemented capabilities**, **foundational prototypes in active development**, and **planned future milestones**.

---

## 🗺️ Version Horizon & Executive Status

| Version | Focus | Core Deliverables | Implementation Status | Tracking Reference |
|---|---|---|---|---|
| **v0.1** | **Core Remediation Loop (MVP)** | Autonomous finding ingestion, AST investigation, guardrailed patch synthesis, sandbox validation, evidence PR automation, MuleRun workflow engine, QoderWork desktop agent, and SOC TUI. | ✅ **Completed & Released** | [Release v0.1.0](https://github.com/kavix/OpenShomer/releases/tag/v0.1.0) |
| **v0.2** | **Framework Ecosystems & Richer Graphs** | Static AST audits for LangChain, LlamaIndex, CrewAI multi-agent delegations, Skill file command fences, official MCP server, and OWASP LLM static rules. | ✅ **Completed & Released** | [Release v0.2.0](https://github.com/kavix/OpenShomer/releases/tag/v0.2.0) |
| **v0.4** | **RAG & Vector Store Security** | AST retriever query inspection for multi-tenant isolation, automated safe Python AST diffs, context poisoning inspection, and in-flight chunk sanitization. | ✅ **Completed & Merged** | [PR #104](https://github.com/kavix/OpenShomer/pull/104) (Closes [#100](https://github.com/kavix/OpenShomer/issues/100)) |
| **v0.3** | **Advanced Red-Teaming & Tool Chaining** | Multi-turn conversational crescendo jailbreak simulations, tool-chaining exploit graph analysis, and dynamic parameter tampering. | 🟡 **Active Development** (Foundational Prototypes) | [Issue #99](https://github.com/kavix/OpenShomer/issues/99) |
| **v0.5** | **Runtime Observability & Live AI Firewall** | Live inference token inspection proxy, streaming latency telemetry, and tamper-evident cryptographic Human-in-the-Loop (HITL) approval gates. | 🟡 **Active Development** (Foundational Prototypes) | [Issue #101](https://github.com/kavix/OpenShomer/issues/101), [Issue #102](https://github.com/kavix/OpenShomer/issues/102) |
| **v0.6** | **Developer Experience & IDE Tooling** | Real-time VS Code / JetBrains language server extension for prompt and tool permission linting during development. | ⏳ **Planned** (Backlog) | [Issue #103](https://github.com/kavix/OpenShomer/issues/103) |

---

## 1. ✅ Fully Implemented Capabilities

### A. Autonomous Security Loop (Find → Investigate → Rewrite → Red-Team → Prove → PR)
- **Finding Ingestion API (`app/api/findings.py`)**: FastAPI REST endpoints for finding registration, triage, investigation, and automated resolution.
- **LLM Reasoning Providers (`app/agents/providers.py`)**: Unified provider interface with support for Alibaba Cloud Qwen (`dashscope`), OpenAI (`openai`), and Google Gemini (`google-genai`).
- **Investigation Agent (`app/agents/investigator.py`)**: Autonomous diagnostic agent using read-only repository inspection tools (`app/agents/tools.py`).
- **Remediation Engine (`app/agents/remediator.py`)**: Precision patch generator bounded by deterministic security guardrails (`app/validation/guardrails.py`) enforcing diff size (<150 lines), unauthorized scope boundaries, permission reduction, and syntax validation.
- **Validation Sandbox (`app/validation/sandbox.py`)**: Isolated ephemeral directory and Docker container test runner ensuring zero execution outside target sandboxes.
- **Adversarial Red-Team Suite (`app/validation/redteam.py`)**: 156-case automated test suite covering direct prompt injections, role-play jailbreaks, delimiter hijacking, and over-permissioned tool abuse.
- **Git & PR Automation (`app/github/`)**: Automated Git branch management, signature commits, and PyGithub pull request creation with before/after security proof.
- **Zero-Config Developer CLI (`app/cli.py`)**: Typer-based CLI supporting `openshomer scan`, `fix`, `auto-pr`, `mulerun`, `tui`, and exports to SARIF and AIBOM standards.
- **MuleRun Workflow Runtime (`app/mulerun/`)**: Event-driven orchestrator with GitHub HMAC-SHA256 webhook ingress and live sandbox telemetry streaming.
- **QoderWork Desktop Agent (`app/qoderwork/agent.py`)**: Autonomous 4-stage lifecycle (`Trigger` → `Investigate` → `Action` → `Resolved`).
- **Terminal SOC UI (`app/tui/app.py`)**: Dual-pane Textual terminal dashboard for security analysts.

### B. Multi-Framework Agent Graph Auditing
- **Agent Skill Files (`app/frameworks/skills.py`)**: Auditing and bash command fencing for `SKILL.md` and `skills/**` configurations.
- **LangChain Agents (`app/frameworks/langchain.py`)**: Unbounded subshell `Tool` detection and `AgentExecutor` runaway execution protections.
- **LlamaIndex Agents (`app/frameworks/llamaindex.py`)**: Dangerous `FunctionTool` primitive validation and `ReActAgent` safeguards.
- **CrewAI Multi-Agent Delegation (`app/frameworks/crewai.py`)**: Auditing unconstrained multi-agent delegation (`allow_delegation=True`) paired with privileged tool access.
- **Official MCP Server (`app/mcp/server.py`)**: Model Context Protocol integration providing tool audit, agent scanning, and prompt red-teaming over MCP.
- **OWASP LLM Top 10 Static Rules (`app/validation/static.py`)**: Deterministic detection for LLM01 (Prompt Injection), LLM02 (Sensitive Information Disclosure), LLM06 (Excessive Agency), and LLM07 (System Prompt Leakage).

### C. RAG & Vector Store Security Pipeline (v0.4 — PR #104 / Issue #100)
- **Vector Retrieval AST Inspection (`app/frameworks/langchain.py`, `app/frameworks/llamaindex.py`)**: Static AST analyzer that flags missing multi-tenant metadata filter dictionaries and unbounded `top_k` retrieval parameters (`MISSING_VECTOR_METADATA_FILTER`).
- **Automated Safe AST Remediation (`app/qoder/python_ast.py`)**: AST re-writer that programmatically injects parameterized `{"tenant_id": tenant_id}` filter dictionaries and caps `k <= 50` in Python source files without duplicating keyword arguments.
- **Threat & Context Poisoning Inspection (`app/frameworks/rag_security.py`)**: Heuristic and regex engine detecting indirect prompt injections, system role spoofing, code execution payloads, and canary credential leaks in retrieved chunks.
- **In-Flight Chunk Sanitization (`app/runtime/firewall.py`)**: Real-time redaction hook intercepting adversarial text before LLM context ingestion.

---

## 2. 🟡 Foundational Prototypes (Active Development)

These modules have functional core implementations and unit tests in the codebase, but are undergoing production hardening:

| Component | Code Location | Implemented Today | Under Active Development |
|---|---|---|---|
| **Multi-Turn Crescendo Simulator (v0.3)** | `app/redteam/multiturn.py` | Deterministic multi-step crescendo attack scenarios (e.g., shell privilege escalation, persona hypnosis) and basic turn progression logic. | Adaptive LLM-driven adversarial multi-turn attacker loop and non-linear branching evaluation. |
| **Tool-Chaining Exploit Detector (v0.3)** | `app/redteam/multiturn.py` | Linear sequence pattern matcher flagging unsafe source-to-sink flows (e.g., `read_web` $\rightarrow$ `run_shell`). | Dynamic taint-tracking graph engine analyzing data dependencies across arbitrary multi-agent execution DAGs. |
| **Runtime AI Firewall Sidecar (v0.5)** | `app/runtime/firewall.py` | In-memory token rate-limiting, destructive command blocking (`rm -rf`, `mkfs`), and dynamic HITL escalation heuristics. | Production streaming token reverse-proxy sidecar (e.g., Envoy/eBPF integration) with sub-millisecond wire interception. |
| **Cryptographic HITL Gate Provider (v0.5)** | `app/hitl/gates.py` | Basic HMAC request signing, approval state tracking, and resolution verification. | Binding approval decision tokens to resolved parameter digests, eliminating hardcoded fallback secrets, and Slack/Discord interactive webhooks ([Issue #102](https://github.com/kavix/OpenShomer/issues/102)). |

---

## 3. ⏳ Planned Capabilities (Not Yet Implemented)

The following deliverables are scheduled on the roadmap and will be tracked via dedicated milestone issues:

1. **IDE & Developer Experience (v0.6 / [Issue #103](https://github.com/kavix/OpenShomer/issues/103))**:
   - Real-time Language Server Protocol (LSP) extension for VS Code and JetBrains IDEs.
   - Inline linting of system prompts, agent skill definitions, and tool permission scopes as developers type.
2. **Production Packaging & Distribution ([Issue #28](https://github.com/kavix/OpenShomer/issues/28))**:
   - Official PyPI package distribution (`pip install openshomer`).
   - Official multi-architecture Docker container images published to GitHub Container Registry (`ghcr.io`).
3. **Interactive Remediation Web Dashboard ([Issue #23](https://github.com/kavix/OpenShomer/issues/23))**:
   - Standalone lightweight web UI visualizing before/after AST diffs, red-team execution traces, and telemetry playback.
4. **Persistent Multi-Tenant Storage Layer ([Issue #21](https://github.com/kavix/OpenShomer/issues/21))**:
   - SQLite and PostgreSQL storage adapter via SQLModel replacing the in-memory finding database.
