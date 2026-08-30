# OpenShomer Documentation Index & Knowledge Map

Welcome to the **OpenShomer Documentation Hub**. This index categorizes all technical guides, architectural specifications, threat models, and integration manuals.

---

## 🗺️ Documentation Knowledge Map

```mermaid
graph TD
    Root["📖 OpenShomer Documentation Hub"]

    Root --> G1["🚀 1. Getting Started & Operations"]
    Root --> G2["🏗️ 2. Core Architecture & Theory"]
    Root --> G3["🛡️ 3. Security Standards & Frameworks"]
    Root --> G4["🧠 4. AI Ecosystems & Providers"]
    Root --> G5["📚 5. Repository Wiki & Governance"]

    G1 --> U1["• User & Setup Guide (docs/USER_GUIDE.md)"]
    G1 --> U2["• SOC Terminal UI Guide (docs/TUI_GUIDE.md)"]
    G1 --> U3["• How It Works (docs/HOW_IT_WORKS.md)"]

    G2 --> A1["• Deep Architecture (docs/ARCHITECTURE.md)"]
    G2 --> A2["• Use Cases & Scenarios (docs/USE_CASES.md)"]

    G3 --> S1["• Threat Model & Red-Team (docs/wiki/Threat-Model.md)"]
    G3 --> S2["• Operational Rules & Policy (docs/RULES.md)"]

    G4 --> Q1["• Alibaba Cloud & Qwen Suite (docs/ALIBABA_QWEN_GUIDE.md)"]

    G5 --> W1["• Developer Setup (docs/wiki/Developer-Setup.md)"]
    G5 --> W2["• Platform Roadmap (docs/wiki/Roadmap.md)"]
```

---

## 1. Getting Started & User Guides

| Document | Purpose | Target Audience |
|---|---|---|
| 📖 **[User & Setup Guide](USER_GUIDE.md)** | Step-by-step installation (`brew`, `uv`, source), GitHub PR automation setup, environment configuration, and CI/CD actions. | Developers, DevOps, SecOps |
| 💻 **[Terminal UI (TUI) SOC Guide](TUI_GUIDE.md)** | Keyboard shortcuts, interactive dual-pane dashboard, and live telemetry log operational manual. | SOC Analysts, Developers |
| 💡 **[How It Works](HOW_IT_WORKS.md)** | Conceptual overview of the **Find $\rightarrow$ Investigate $\rightarrow$ Rewrite $\rightarrow$ Red-Team $\rightarrow$ Prove $\rightarrow$ PR** autonomous loop. | General Engineers |

---

## 2. Technical Architecture & Use Cases

| Document | Purpose | Target Audience |
|---|---|---|
| 🏗️ **[Deep Architecture](ARCHITECTURE.md)** | Complete breakdown of **MuleRun** (Workflow Runtime), **Qoder** (AST Synthesizer), and **QoderWork** (Desktop Agent). | Software Architects |
| 📋 **[Use Cases & Flow Scenarios](USE_CASES.md)** | Detailed real-world scenarios across SRE/DevOps, SQL Analytics, Customer Support, and MCP integrations. | AppSec Engineers |

---

## 3. Advanced Integrations & AI Backbones

| Document | Purpose | Target Audience |
|---|---|---|
| 🧠 **[Alibaba Cloud & Qwen Security Suite](ALIBABA_QWEN_GUIDE.md)** | Guide for Qwen-2.5-Coder AST synthesis, Content Guardrails moderation, and high-throughput batch red-teaming. | AI Engineers |

---

## 4. Threat Models, Governance & Wiki

| Document | Purpose | Target Audience |
|---|---|---|
| 🛡️ **[Threat Model & Attack Surface](wiki/Threat-Model.md)** | Analysis of OWASP LLM Top 10, MITRE ATLAS tactics, and prompt injection threat surfaces. | Security Teams |
| 🛠️ **[Developer Setup](wiki/Developer-Setup.md)** | Virtual environments, pytest test execution, `uv` workflows, and Ruff linting standards. | Contributors |
| 🗺️ **[Wiki Roadmap](wiki/Roadmap.md)** | Multi-turn jailbreak simulations, containerized sandboxes, and enterprise roadmaps. | All Stakeholders |
