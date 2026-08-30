# OpenShomer — Deep Technical Architecture

This document provides a comprehensive technical breakdown of OpenShomer's architectural components, data contracts, validation lifecycles, and security boundary guarantees.

---

## 🏛️ System Architecture

```mermaid
graph TD
    subgraph RUNTIME["1. Workflow Runtime (MuleRun)"]
        MR["MuleRun Runtime Engine<br/>app/mulerun/runtime.py"]
        WH["GitHub Webhook Ingress (HMAC-SHA256)<br/>app/mulerun/webhooks.py"]
        QWEN["Alibaba Cloud Qwen Reasoning Gateway<br/>app/agents/providers.py"]
        TELEM["Live Sandbox Telemetry Streamer"]
        
        WH --> MR
        MR <--> QWEN
        MR <--> TELEM
    end

    subgraph AGENTS["2. Autonomous Agent Layer (QoderWork)"]
        QW["QoderWork Desktop Agent Loop<br/>Trigger → Investigate → Action → Resolved<br/>app/qoderwork/agent.py"]
        FW["Richer Agent Graph Scanners<br/>LangChain, LlamaIndex, CrewAI, Skills<br/>app/frameworks/"]
        IA["Investigation Agent<br/>app/agents/investigator.py"]
        RT["Repo Tool Belt<br/>app/agents/tools.py"]
        
        MR --> QW
        QW --> FW
        QW --> IA
        IA <--> RT
    end

    subgraph REMEDIATION["3. Precision Remediation Engine (Qoder)"]
        QD["Qoder Agentic IDE Backbone<br/>app/qoder/ide.py"]
        DS["AST & Schema Diff Synthesizer<br/>app/qoder/diff_synthesizer.py"]
        PF["Defensive Prompt Fencing Engine<br/>app/qoder/prompt_fencing.py"]
        
        QW --> QD
        QD --> DS
        QD --> PF
    end

    subgraph VALIDATION["4. Validation & Red-Team Layer"]
        GR["Patch Guardrails<br/>app/validation/guardrails.py"]
        SB["Sandbox Runner<br/>app/validation/sandbox.py"]
        ST["Static Policy Checker<br/>app/validation/static.py"]
        AT["Adversarial Red-Team Suite (156 cases)<br/>app/validation/redteam.py"]

        QD --> GR
        GR --> SB
        SB --> ST
        SB --> AT
        SB --> TELEM
    end

    subgraph DELIVERY["5. Git & PR Delivery Layer"]
        BM["Branch Manager<br/>app/github/branches.py"]
        CM["Commit Manager<br/>app/github/commits.py"]
        PM["Pull Request Generator<br/>app/github/pull_requests.py"]

        AT -- "Pass" --> BM
        BM --> CM
        CM --> PM
        PM --> GH["GitHub API (Evidence-Backed PR)"]
    end

    style RUNTIME fill:#e8f0fe,stroke:#4285f4
    style AGENTS fill:#e6f4ea,stroke:#34a853
    style REMEDIATION fill:#fef7e0,stroke:#fbbc05
    style VALIDATION fill:#fce8e6,stroke:#ea4335
    style DELIVERY fill:#f3e8fd,stroke:#a142f4
```

---

## 🔄 Finding Lifecycle & State Machine

```mermaid
stateDiagram-v2
    [*] --> INGESTED: Finding Ingested via API
    INGESTED --> INVESTIGATING: Agent starts diagnosis
    INVESTIGATING --> INVESTIGATED: Structured InvestigationResult produced
    
    INVESTIGATED --> REMEDIATING: Remediation Engine generates rewrite
    REMEDIATING --> REMEDIATED: Patch generated
    REMEDIATING --> NEEDS_HUMAN: Guardrails failed (out of bounds)
    
    REMEDIATED --> VALIDATING: Sandbox created & Red-Team executed
    VALIDATING --> VALIDATED: Static + Red-Team passed
    VALIDATING --> REJECTED: Red-Team or Static failed
    
    VALIDATED --> PR_OPENED: Branch created & GitHub PR opened
    PR_OPENED --> [*]
    REJECTED --> [*]
    NEEDS_HUMAN --> [*]
```

---

## 🛡️ Validation & Guardrail Decision Flow

```mermaid
flowchart TD
    Start["Generated Patch Diff"] --> Scope{"Scope Check<br/>Touches only affected files?"}
    Scope -- "No" --> Reject1["Reject: Unauthorized file modifications"]
    Scope -- "Yes" --> Size{"Size Check<br/>Lines within blast radius limit (< 150)?"}
    
    Size -- "No" --> Reject2["Reject: Diff size exceeds maximum threshold"]
    Size -- "Yes" --> PermCheck{"Permission Reduction Check<br/>No new high-risk permissions added?"}
    
    PermCheck -- "No" --> Reject3["Reject: Unrestricted permissions added"]
    PermCheck -- "Yes" --> Sand["Execute in Isolated Docker Sandbox"]
    
    Sand --> RedTeam{"Adversarial Red-Team Suite<br/>100% test cases blocked?"}
    RedTeam -- "No" --> Reject4["Reject: Attack path still exploitable"]
    RedTeam -- "Yes" --> Approve["APPROVED FOR PULL REQUEST"]

    style Approve fill:#e6f4ea,stroke:#34a853
    style Reject1 fill:#fce8e6,stroke:#ea4335
    style Reject2 fill:#fce8e6,stroke:#ea4335
    style Reject3 fill:#fce8e6,stroke:#ea4335
    style Reject4 fill:#fce8e6,stroke:#ea4335
```

---

## 🔒 Security Guarantees
1. **Read-Only Investigation:** Agent inspection tools cannot modify workspace files or run shell commands outside the target repo boundary.
2. **Deterministic Disposal:** LLM proposals are validated by strict Python guardrails and deterministic regex before entering the sandbox.
3. **Isolated Test Execution:** Red-team tests run in ephemeral sandbox directories/Docker containers isolated from host credentials.
4. **Non-Destructive Git Operations:** Patches are committed to isolated security branches; `main` branch is never touched directly.
