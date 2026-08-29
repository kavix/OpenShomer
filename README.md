# PromptGuard

**An open-source agentic security engineer for LLM system prompts, agent configs, tool definitions, and MCP servers.**

It finds risky patterns in AI agent configurations, investigates the full agent graph, generates minimal safe rewrites, validates them with adversarial red-teaming inside a sandbox, and opens evidence-backed pull requests.

> Detection is not enough. PromptGuard closes the loop: **Find → Investigate → Rewrite → Red-team → Prove → PR**.

---

## Why PromptGuard?

Traditional AppSec tools ignore the new attack surface:

- System prompts that are overly permissive
- Tools / MCP servers with excessive permissions
- Missing human-in-the-loop gates
- Prompt-injection and data-exfiltration paths
- Agent skills that can be abused

Most existing tools only **detect**. Almost nothing **remediates** with validation.

PromptGuard treats AI agent configuration as first-class code that must be investigated, fixed, and proven safe before it reaches a human reviewer.

```
Risky Prompt / Config → Alert (what most tools do)
Risky Prompt / Config → Investigate → Minimal Rewrite → Adversarial Validation → Evidence-backed PR (what PromptGuard does)
```

---

## MVP Scope (v0.1)

The first version is deliberately narrow and high-confidence.

### In Scope
- System prompts (`.prompt`, `system.md`, inline prompts in code)
- Tool definitions and permission manifests
- MCP server configuration files
- Basic agent skill / tool-calling configs
- Detection of these high-impact patterns:
  - Over-permissioned tools (file system, network, shell, payment, etc.)
  - Missing human approval gates on high-risk actions
  - Clear prompt-injection surfaces
  - Obvious data-exfiltration paths
  - Hardcoded secrets or credentials inside prompts/configs

### Out of Scope for MVP
- Full RAG pipeline analysis
- Multi-agent orchestration graphs (beyond single agent + tools)
- Runtime monitoring / live agent protection
- Automatic merging of PRs
- Complex multi-file agent frameworks (LangGraph, CrewAI deep graphs) — later versions

### Core Workflow
1. **Ingest** a finding or scan a repository for agent configs
2. **Investigate** the agent graph using controlled tools (`read_file`, `search_code`, `list_tools`, `get_prompt_context`)
3. **Generate** a minimal safe rewrite of the prompt / config
4. **Validate** inside an isolated sandbox with adversarial red-team tests
5. **Open** a pull request only if every check passes

Every AI-generated change is treated as **untrusted** until it survives deterministic + adversarial validation.

---

## Architecture (MVP)

```
Finding / Repo Scan
        ↓
 Investigation Agent  →  structured risk report
        ↓
 Remediation Engine   →  minimal rewrite (prompt + config)
        ↓
 Validation Sandbox
   ├── Static checks
   ├── Permission diff
   ├── Adversarial red-team suite
   └── Behavioral equivalence (where possible)
        ↓
 GitHub PR (only on full pass)
```

### Components

| Component              | Purpose                                      | MVP Technology          |
|------------------------|----------------------------------------------|-------------------------|
| API                    | Receive findings & control workflow          | FastAPI                 |
| Finding Manager        | Store and track risks                        | Python + PostgreSQL     |
| Investigation Agent    | Analyze prompts, tools, MCP configs          | Python + LLM            |
| Remediation Engine     | Generate minimal safe rewrites               | Coding model / LLM      |
| Red-Team Validator     | Adversarial testing of the new config        | Custom + LLM attackers  |
| Sandbox                | Isolated execution of validation             | Docker                  |
| Git Manager            | Branches, commits, PRs                       | GitHub API              |
| Orchestration          | Coordinate the linear workflow               | Simple Python / later MuleRun |

### Security Model
- AI output is never trusted by default
- Every rewrite must pass:
  - Static policy checks
  - Permission reduction verification
  - Adversarial prompt-injection & tool-abuse tests
  - No new high-risk capabilities introduced
- Only then is a PR opened for human review

---

## Example Flow

**Input finding:**
```json
{
  "id": "PG-001",
  "type": "OVER_PERMISSIONED_TOOL",
  "severity": "HIGH",
  "file": "agent/tools.yaml",
  "tool": "run_shell",
  "issue": "Shell tool has no human approval gate and unrestricted command scope",
  "repository": "customer-support-agent"
}
```

**Investigation result (structured):**
```json
{
  "finding": "PG-001",
  "root_cause": "run_shell tool lacks approval gate and command allow-list",
  "affected_files": ["agent/tools.yaml", "prompts/system.md"],
  "recommended_fix": "Add human-in-the-loop gate + restrict to safe command prefix",
  "confidence": 0.93,
  "risk": "HIGH"
}
```

**Minimal rewrite (example):**
```diff
- name: run_shell
-   description: Execute any shell command
-   permissions: ["shell:unrestricted"]
+ name: run_shell
+   description: Execute approved shell commands only
+   permissions: ["shell:restricted"]
+   requires_approval: true
+   allowed_prefixes: ["ls", "cat", "grep", "echo"]
```

**Validation report:**
```
✓ Permission surface reduced
✓ Adversarial injection tests: 12/12 blocked
✓ No new high-risk tools introduced
✓ Original risky behavior no longer possible
Result: APPROVED FOR PR
```

---

## Project Structure (MVP)

```
promptguard/
├── app/
│   ├── api/
│   │   ├── findings.py
│   │   └── repositories.py
│   ├── agents/
│   │   ├── investigator.py
│   │   └── remediation.py
│   ├── validation/
│   │   ├── static.py
│   │   ├── redteam.py
│   │   └── sandbox.py
│   ├── github/
│   │   ├── branches.py
│   │   ├── commits.py
│   │   └── pull_requests.py
│   ├── models/
│   │   └── findings.py
│   └── main.py
├── redteam/
│   └── suites/                  # Adversarial test cases
├── demo/
│   └── vulnerable-agent/        # Sample risky agent for testing
├── docker/
│   └── sandbox/
├── tests/
├── requirements.txt
├── docker-compose.yml
└── README.md
```

---

## Quick Start (Planned)

```bash
git clone https://github.com/<your-username>/promptguard.git
cd promptguard

python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Start API
uvicorn app.main:app --reload
```

API will be available at `http://localhost:8000` with docs at `/docs`.

---

## Roadmap

| Version | Focus                              | Highlights                                      |
|---------|------------------------------------|-------------------------------------------------|
| **v0.1**    | Core Loop (current)                | System prompts + tool/MCP configs, basic red-team, GitHub PRs |
| v0.2    | Richer Agent Graphs                | Multi-tool agents, skill files, basic LangChain/LlamaIndex support |
| v0.3    | Advanced Red-Teaming               | Adaptive attackers, multi-turn jailbreaks, tool-chaining attacks |
| v0.4    | RAG & Memory Security              | Vector store permissions, retrieval prompt hardening |
| v0.5    | Runtime Feedback Loop              | Ingest live agent traces and close the loop from production |

### Design Principles
1. **Start extremely narrow** — one high-value config type at a time.
2. **AI proposes, deterministic + adversarial systems dispose**.
3. **Minimal changes only** — never rewrite more than necessary.
4. **Evidence travels with every PR**.
5. **Human always has the final merge decision**.

---

## What PromptGuard Is Not
- Not another prompt scanner that only opens issues
- Not a general coding agent
- Not a runtime agent firewall (that is a different layer)
- Not a replacement for human security review

It is the missing remediation engine between “we found a risky agent config” and “a verified, minimal, reviewable fix exists”.

---

## Contributing

Good first contributions:
- New detection rules for risky patterns
- Additional red-team test cases
- Support for more config formats (YAML, JSON, TOML, Python dicts, etc.)
- Better investigation tools
- Improved minimal-rewrite strategies
- Documentation and demo agents

Open an issue before large architectural changes.

---

## Status

**Project Status: Early Design / MVP Definition**

- [x] Core idea and security model defined
- [x] MVP scope locked (prompts + tools + MCP)
- [ ] Finding ingestion
- [ ] Investigation agent
- [ ] Remediation engine
- [ ] Red-team validation suite
- [ ] Sandbox
- [ ] GitHub PR automation

---

## License

MIT (planned)

---

**PromptGuard**  
Find the risky agent config. Rewrite it safely. Prove the attack path is closed. Open the PR.
