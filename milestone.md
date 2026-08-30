# OpenShomer — Milestones & Build Guide

This is the working guide for the OpenShomer project board. It answers three things for every phase: **what gets added**, **how you add it**, and **how you know it's done**.

---

## How a milestone is defined here

A milestone in this project is **not** "a bunch of related tasks." It follows one specific rule, repeated every time:

> **One milestone = one new capability that works end-to-end on its own, proven by a single command or test run — not a pile of half-built pieces.**

Practically, that means every milestone below has the same four parts:

| Part | What it means |
|---|---|
| **What you add** | The exact files/modules that get created — maps 1:1 to the architecture plan |
| **How** | The concrete steps, in order, to build it |
| **Definition of Done (DoD)** | A command, test, or demo that either passes or doesn't — no judgment calls |
| **GitHub mapping** | 1 milestone = 1 GitHub Milestone; each numbered step below = 1 Issue, labelled `phase:N` + a cell label (`cell:api`, `cell:agent`, `cell:validation`, `cell:git`) |

If a step can't be checked off by running something, it isn't done yet — "looks right" doesn't count.

---

## Phase 0 — Vulnerable Agent Demo Fixture *(prerequisite)*

**What you add:** a demo target repo or fixture directory, `demo/vulnerable-agent/` (or separate repo `vulnerable-agent-fixture`), representing an AI agent with configuration risks.

```
demo/vulnerable-agent/
├── agent/
│   ├── config.yaml          ← agent configuration
│   └── tools.yaml           ← tool definitions with over-permissioned shell / file access
├── prompts/
│   └── system.md            ← permissive system prompt missing security boundaries
├── mcp/
│   └── mcp_servers.json     ← MCP server configs with unrestricted scope
└── tests/
    └── test_agent.py        ← baseline agent functionality tests
```

**How:**
1. Create `prompts/system.md` with an unrestricted system prompt vulnerable to direct instruction overriding.
2. Define `agent/tools.yaml` containing high-risk tools (e.g. unrestricted `run_shell` lacking human approval gates or command allow-lists).
3. Add `mcp/mcp_servers.json` exposing broad tool access without permission scoping.
4. Write a baseline functional test in `tests/test_agent.py` to ensure the agent works prior to remediation.

**Definition of Done:** `pytest tests/test_agent.py` passes, and the static config contains verifiable risks (`OVER_PERMISSIONED_TOOL`, `MISSING_APPROVAL_GATE`, `PROMPT_INJECTION_SURFACE`).

**GitHub mapping:** Milestone "v0.1 — Phase 0: Fixture". Issues: `Create vulnerable-agent fixture`.

---

## Phase 1 — Finding Ingestion API

**What you add:**
```
app/models/findings.py     ← Finding, FindingType, Severity, FindingReceipt (Pydantic)
app/api/findings.py        ← POST /findings, GET /findings/{id}, GET /findings, GET /health
app/main.py                ← FastAPI application entrypoint
tests/test_findings.py     ← API test suite
requirements.txt           ← fastapi, uvicorn, pydantic, pytest, httpx
Dockerfile
docker-compose.yml
.env.example
```

**How:**
1. Define the finding schema in `app/models/findings.py` supporting agent security finding types: `OVER_PERMISSIONED_TOOL`, `MISSING_APPROVAL_GATE`, `PROMPT_INJECTION_SURFACE`, `DATA_EXFILTRATION_PATH`, and `HARDCODED_SECRET_IN_PROMPT`.
2. Stand up a FastAPI app in `app/main.py` & `app/api/findings.py` with an in-memory/structured store.
3. Write `pytest` tests that post a finding and retrieve it back.
4. Containerize with a minimal `Dockerfile` and `docker-compose.yml`.

**Definition of Done:** `pytest -q` passes; `curl -X POST localhost:8000/findings -d @finding.json` returns `{"status": "received", ...}` and `GET /findings/SHOMER-001` returns the finding.

**GitHub mapping:** Milestone "v0.1 — Phase 1: Ingestion". Issues: `Define Finding schema`, `Build POST/GET /findings`, `Write ingestion tests`, `Dockerize API`.

---

## Phase 2 — Investigation Agent

**What you add:**
```
app/agents/__init__.py
app/agents/tools.py          ← read_file(), search_code(), list_tools(), get_prompt_context() (read-only repo tools)
app/agents/schemas.py        ← InvestigationResult (Pydantic): finding, root_cause, affected_files, recommended_fix, confidence, risk
app/agents/investigator.py   ← LLM agent loop with tool calling, forcing structured InvestigationResult output
requirements.txt             ← + anthropic / google-genai, gitpython
app/main.py                  ← + POST /findings/{id}/investigate
```

**How:**
1. Write `tools.py` first as deterministic read-only functions operating on the target repo workspace.
2. Define `InvestigationResult` in `schemas.py` with strict validation (root cause, affected files, recommended fix, confidence, risk).
3. In `investigator.py`, run the tool-calling agent loop to inspect prompts, tool definitions, and MCP configurations, validating the final output against `InvestigationResult`.
4. Wire `POST /findings/{id}/investigate` in `main.py`: lookup finding, run investigation agent, store and return structured result.

**Definition of Done:** calling `POST /findings/SHOMER-001/investigate` against the vulnerable fixture returns schema-valid JSON correctly diagnosing the over-permissioned tool / prompt surface without manual edits.

**GitHub mapping:** Milestone "v0.1 — Phase 2: Investigation". Issues: `Repo tool belt`, `InvestigationResult schema`, `Investigator agent loop`, `/investigate endpoint`, `Test against demo fixture`.

---

## Phase 3 — Remediation Engine + Patch Guardrails

**What you add:**
```
app/agents/remediation.py     ← generates minimal safe rewrites for prompts, tools, and MCP configs
app/validation/__init__.py
app/validation/guardrails.py  ← scope check, size check, permission reduction diff, syntax validation
app/main.py                   ← + POST /findings/{id}/remediate
```

**How:**
1. `remediation.py` prompts the model to produce a minimal safe rewrite strictly limited to `affected_files`, capturing changes as a clean git diff.
2. `guardrails.py` performs deterministic checks:
   - `check_scope(diff, allowed_files)`: ensures only affected files were changed.
   - `check_size(diff, max_lines)`: ensures patch is minimal and not an arbitrary rewrite.
   - `check_permission_reduction(diff)`: verifies permissions were strictly reduced/restricted.
   - `check_syntax(diff)`: ensures valid YAML/JSON/Markdown syntax.
3. If guardrails fail, retry with feedback or mark finding as `needs_human`.
4. Wire `POST /findings/{id}/remediate`: runs remediation + guardrails, storing the resulting diff.

**Definition of Done:** on the demo fixture, produces a minimal diff that adds required approval gates / restricts tool commands; rejects arbitrary or overly broad edits.

**GitHub mapping:** Milestone "v0.1 — Phase 3: Remediation". Issues: `Remediation engine`, `Scope guardrail`, `Size guardrail`, `Permission reduction check`, `Syntax guardrail`, `Retry/needs_human path`.

---

## Phase 4 — Validation Sandbox & Adversarial Red-Teaming + GitHub PR

**What you add:**
```
app/validation/sandbox.py     ← Docker SDK runner: isolated execution environment
app/validation/static.py      ← deterministic policy and permission diff checks
app/validation/redteam.py     ← adversarial red-team suite (prompt injection & tool abuse scenarios)
app/github/__init__.py
app/github/branches.py        ← creates branch from diff
app/github/commits.py         ← commits patched files
app/github/pull_requests.py   ← opens PR with comprehensive evidence report (PyGithub)
app/main.py                   ← + POST /findings/{id}/resolve (runs pipeline end-to-end)
requirements.txt              ← + docker, PyGithub, requests
.env.example                  ← + GITHUB_TOKEN
```

**How:**
1. `sandbox.py`: spins up an isolated Docker container with the target repo and applied patch.
2. `static.py` & `redteam.py`: runs static checks and executes automated red-team test cases against the rewritten prompt/config to confirm the attack vector is neutralized.
3. If all checks pass, `branches.py` → `commits.py` → `pull_requests.py` create the branch, commit changes, and open a PR with the full validation report.
4. `POST /findings/{id}/resolve`: executes Phases 2 → 3 → 4 end-to-end.

**Definition of Done:** running the full pipeline against the demo fixture produces a verified, mergeable GitHub PR with an attached evidence report confirming the vulnerability is resolved.

**GitHub mapping:** Milestone "v0.1 — Phase 4: Validation & PR". Issues: `Docker sandbox runner`, `Static check runner`, `Adversarial red-team suite`, `Branch/commit/PR creation`, `Evidence report template`, `End-to-end /resolve endpoint`.

---

## Roadmap & Milestone Status

| Version | Focus | Details | Status |
|---|---|---|---|
| **v0.1 — Core Loop (MVP)** | Prompts, Tools, MCPs, Sandbox & PRs | Single-agent configs, prompt fences, Docker sandbox, evidence PRs, MuleRun, QoderWork, Qoder | **Completed & Released** |
| **v0.2 — Richer Agent Graphs** | Multi-tool & skill frameworks | Support for LangChain, LlamaIndex, CrewAI, and complex skill definitions. | **Completed & Released** |
| **v0.3 — Advanced Red-Teaming** | Adaptive adversarial attacks | Multi-turn jailbreaks, indirect prompt injection across tools, and tool-chaining exploits. | *In Design* |
| **v0.4 — RAG & Memory Security** | Vector store & memory hardening | Permission checks on retrieval stores, sanitization of retrieved context, memory poisoning defense. | *Planned* |
| **v0.5 — Runtime Feedback Loop** | Live trace ingestion | Ingest production agent traces to detect anomalies and trigger automated remediation. | *Planned* |

---

## Quick Reference: Milestone → GitHub Setup

1. Create one **GitHub Milestone** per phase (`v0.1 — Phase 1`, `v0.1 — Phase 2`, …)
2. Create one **Issue** per numbered step in that phase's "How" section above, assign it to the milestone
3. Label each issue with `phase:N` and the relevant cell (`cell:api`, `cell:agent`, `cell:validation`, `cell:git`)
4. A milestone is only closed when its **Definition of Done** command/test has passed.
