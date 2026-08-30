# OpenShomer — Progress & Release Update

**Releases:** [v0.1.0](https://github.com/kavix/OpenShomer/releases/tag/v0.1.0) & [v0.2.0](https://github.com/kavix/OpenShomer/releases/tag/v0.2.0)
**Author:** @kavix

---

## TL;DR

> OpenShomer **v0.1 (Core Loop MVP)** and **v0.2 (Richer Agent Graphs)** are complete, tested (49 passing tests), built, and released. OpenShomer now features the **MuleRun** AI workflow runtime, the **QoderWork** autonomous desktop security agent, the **Qoder** AI-native diff synthesizer, and full multi-framework support for **LangChain**, **LlamaIndex**, **CrewAI**, and **Agent Skill Files**.

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

---

## Verification & Releases
* **Test Suite**: 49/49 unit, integration, and framework tests passing.
* **Release v0.1.0**: [GitHub Release v0.1.0](https://github.com/kavix/OpenShomer/releases/tag/v0.1.0)
* **Release v0.2.0**: [GitHub Release v0.2.0](https://github.com/kavix/OpenShomer/releases/tag/v0.2.0)
