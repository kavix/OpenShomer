# AI Buildathon — Final Project Submission

- **Event:** AI Buildathon (Organized by IMSSA, University of Kelaniya in partnership with Alibaba Cloud)
- **Team Name:** KODEGAS
- **Participant:** Kavindu Sachinthe Bandara Galkotuwa
- **Email:** galkotu-ec22053@stu.kln.ac.lk
- **Project Name:** OpenShomer

---

## 1. Project Brief

### Problem *
As developers deploy autonomous AI agents and LLMs using tools and MCP (Model Context Protocol) servers, they introduce critical security vulnerabilities: over-permissioned shell/file access, susceptibility to prompt injection, missing human-in-the-loop gates, and hardcoded secrets in prompts. Traditional AppSec tools only scan static code and dump noisy alerts—they do not understand agent execution graphs, cannot fix prompts or tool permissions, and cannot verify if a security fix actually works or breaks agent functionality.

---

### Solution *
**OpenShomer** is an open-source autonomous agentic security engineer that closes the security loop: **Find → Investigate → Rewrite → Red-team in sandbox → Prove → GitHub PR**. 
Instead of just alerting developers, OpenShomer investigates the agent codebase, generates a minimal safe configuration and prompt patch, tests it against adversarial prompt injection and tool abuse attacks inside an isolated Docker sandbox, and automatically opens an evidence-backed Pull Request on GitHub.

---

### AI Features in Your Product *
*(What does AI actually do for your users?)*
1. **Autonomous Security Investigation Agent**: Analyzes system prompts, agent tools, and MCP server configurations using Alibaba Cloud Qwen LLMs to diagnose root causes and determine attack blast radius.
2. **Context-Aware Remediation & Patching**: Synthesizes minimal, safe code and prompt rewrites that strip excessive permissions while preserving the agent's core capabilities and developer intent.
3. **Adversarial Red-Teaming & Content Guardrails**: Automatically executes live prompt injection, jailbreak attempts, and tool hijacking payloads against the patched agent in a sandbox to verify that attacks are blocked before merging code.

---

### Technical Brief *
- **Core Architecture**: Python 3.11+, FastAPI (REST API & MuleRun Webhook runtime), and Pydantic v2 schemas.
- **AI Backbone**: Native integration with **Alibaba Cloud Model Studio (DashScope)** powered by the **Qwen Model Family** (`qwen-2.5-coder`, `qwen-max`, `qwen-plus`, `qwen-turbo`) for deep AST synthesis, strict function calling schemas, and batch safety evaluations.
- **Frameworks Supported**: LangChain, LlamaIndex, CrewAI, Anthropic MCP servers, and raw YAML/JSON agent configs.
- **Sandbox & Validation**: Docker container environment running static AST permission checks, permission surface reduction diffs, and an automated red-team test suite.
- **Developer Interfaces**: Interactive Terminal UI (TUI / Textual) SOC dashboard, unified CLI tool (`uv run openshomer`), and GitHub Actions integration for automated PR review.

---

### Impact *
- **Zero-Effort Remediation**: Reduces the time to fix dangerous AI agent vulnerabilities from days of manual auditing to under 2 minutes of automated, verified patching.
- **Eliminates Alert Fatigue**: Replaces hundreds of static scanner alerts with ready-to-merge GitHub Pull Requests backed by cryptographic execution proofs.
- **Prevents Real-World Exploits**: Hardens enterprise and open-source AI applications against data exfiltration, system prompt leaks, and unauthorized remote code execution.

---

### Roadmap *
- **Phase 1 (Completed / MVP)**: End-to-end remediation pipeline (CLI + TUI + Docker sandbox + GitHub PRs) with native Alibaba Cloud Qwen integration.
- **Phase 2 (Next 3 Months)**: Multi-agent graph vulnerability mapping, interactive Human-in-the-Loop (HITL) approval gates, and a VS Code / IDE extension for live prompt and tool permission linting.
- **Phase 3 (Next 6 Months)**: Real-time runtime AI firewall sidecar proxy for live streaming inference and continuous CI/CD red-teaming benchmarks.

---

## 2. Links & Statement

### Source Repository *
```
https://github.com/kavix/OpenShomer
```
*(Ensure repository visibility on GitHub is set to **Public**)*

---

### Hosted Prototype *
```
https://github.com/kavix/OpenShomer#demo
```
*(If you have a deployed backend URL, e.g. on Render/ECS/MuleRun, paste that live endpoint URL here).*

---

### WhatsApp Number *
*(Provide your active WhatsApp contact with country code, e.g. `+94 7X XXX XXXX`)*

---

### Demo Video
```
https://youtu.be/b9bJ8YaUV3U
```
*(Unlisted YouTube link, 3 minutes walkthrough showing: 1. Vulnerability overview -> 2. OpenShomer scan/investigation -> 3. Sandbox red-teaming -> 4. Automated PR generation).*

---

### Qoder Usage Statement *
Using **Qoder** throughout this buildathon was a game changer for developing OpenShomer from scratch to a production-ready open-source system.

1. **Architecture & Scaffolding**: Qoder accelerated the initial design phase by generating the core FastAPI control plane, Pydantic v2 schemas for agent risk findings, and modular repository structures.
2. **Framework Parsers & AST Synthesis**: Developing AST inspection rules for multiple agent frameworks (CrewAI, LangChain, LlamaIndex, and MCP server configs) was complex. Qoder generated accurate AST visitor patterns and regex guardrails, saving hours of manual parsing.
3. **Alibaba Cloud & Qwen Integration**: Qoder helped scaffold and test our native Alibaba Cloud DashScope integration (`qwen-2.5-coder` and `qwen-plus`), structuring function-calling schemas and parallel batch red-teaming routines.
4. **Testing & Sandbox Hardening**: Qoder assisted in writing our comprehensive adversarial test suites and Docker validation sandboxes, debugging async runtime errors swiftly.

The experience with Qoder was smooth, intuitive, and responsive. Its ability to maintain full codebase context and generate production-grade Python code significantly accelerated our velocity and helped our team deliver a complete, battle-tested solution on schedule.
