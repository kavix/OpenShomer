# OpenShomer User & Setup Guide

This guide covers how to install, configure, and run **OpenShomer** for local development, CLI usage, interactive TUI operations, and automated GitHub Pull Request (PR) remediation in CI/CD pipelines.

---

## 1. Quick Installation

### Method A: Homebrew (macOS & Linux) — Recommended

```bash
# 1. Tap the official OpenShomer repository
brew tap kavix/tap

# 2. Install OpenShomer
brew install openshomer

# 3. Verify installation
openshomer version
```

---

### Method B: From Source (Developers & Contributors)

```bash
# 1. Clone repository
git clone https://github.com/kavix/OpenShomer.git
cd OpenShomer

# 2. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install in editable mode with development dependencies
pip install -e .
```

---

## 2. Setting Up GitHub PR Automation

OpenShomer can automatically open evidence-backed Pull Requests on GitHub when vulnerabilities are detected and validated in the sandbox.

### Step 1: Create a GitHub Personal Access Token (PAT)
1. Go to **GitHub Settings** $\rightarrow$ **Developer settings** $\rightarrow$ **Personal access tokens** $\rightarrow$ **Fine-grained tokens** (or Tokens Classic).
2. Generate a token with the following permissions:
   * **Repository permissions**:
     * `Contents`: **Read & Write** (to create branch and commit patches)
     * `Pull Requests`: **Read & Write** (to open and update PRs)
     * `Metadata`: **Read-Only**

### Step 2: Configure Environment Variables

Export your GitHub credentials in your shell (`~/.zshrc` or `~/.bashrc`):

```bash
# Your GitHub PAT
export GITHUB_TOKEN="ghp_yourPersonalAccessTokenHere123456"

# Optional: Default target repository
export GITHUB_REPOSITORY="owner/target-agent-repo"

# Optional: LLM Provider for advanced reasoning (Alibaba Qwen, OpenAI, or Gemini)
export DASHSCOPE_API_KEY="sk-yourAlibabaQwenKeyHere"
export OPENSHOMER_LLM_PROVIDER="alibaba"
export OPENSHOMER_LLM_MODEL="qwen-plus"
```

*(Note: If you use the GitHub CLI `gh`, OpenShomer will automatically detect your active `gh auth token` if `GITHUB_TOKEN` is not set).*

---

## 3. Running OpenShomer

### 1. Interactive Terminal User Interface (TUI)
Launch the Security Operations Center (SOC) dashboard:

```bash
# Audit the current directory
openshomer tui

# Audit a specific target repository
openshomer tui /path/to/any-agent-repo
```

#### TUI Keyboard Shortcuts:
* `S` — **Scan Workspace**: Runs AST checks and lists findings in the Security Ledger.
* `M` — **Trigger MuleRun**: Tests simulated GitHub repository webhook ingestion.
* `D` — **Qoder Synthesizer**: Generates feature-preserving AST diffs.
* `R` — **Autonomous Loop**: Executes the full 4-stage remediation cycle.
* `P` — **Open Evidence PR**: Validates fixes in sandbox and pushes a real PR to GitHub.
* `Q` — **Quit**: Exits the platform.

---

### 2. Command Line Interface (CLI)

```bash
# 1. Scan a repository and view color-coded table
openshomer scan /path/to/agent-repo

# 2. Output findings as machine-readable JSON
openshomer scan /path/to/agent-repo --json

# 3. Export OASIS SARIF v2.1.0 report for GitHub Advanced Security
openshomer scan /path/to/agent-repo --sarif results.sarif

# 4. Export CycloneDX AI Bill of Materials (AIBOM)
openshomer scan /path/to/agent-repo --aibom aibom.json

# 5. Automatically remediate and open PR on GitHub
openshomer auto-pr /path/to/agent-repo --repo owner/agent-repo
```

---

## 4. Setting Up GitHub Actions CI/CD (Automated PRs on Every Push)

To run OpenShomer automatically in any AI agent repository and open remediation PRs whenever insecure configurations are introduced:

Create `.github/workflows/openshomer-security.yml` in the target repository:

```yaml
name: OpenShomer Security Guardrails

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

jobs:
  security-audit:
    name: Audit & Remediate AI Agent Security
    runs-on: ubuntu-latest

    permissions:
      contents: write
      pull-requests: write
      security-events: write

    steps:
      - name: Checkout Target Repository
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install OpenShomer
        run: |
          pip install git+https://github.com/kavix/OpenShomer.git

      - name: Run OpenShomer Audit & Export SARIF
        run: |
          openshomer scan . --sarif openshomer-results.sarif --no-exit-code

      - name: Upload SARIF to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: openshomer-results.sarif

      - name: Autonomous Security Remediation & PR
        if: github.event_name == 'push'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITHUB_REPOSITORY: ${{ github.repository }}
        run: |
          openshomer auto-pr . --repo ${{ github.repository }}
```

---

## 5. Summary of Supported Agent Frameworks

OpenShomer automatically detects and secures:
1. **YAML & JSON Tool Configs** (`agent/tools.yaml`, AutoGen, Semantic Kernel)
2. **MCP Servers** (`mcp/mcp_servers.json`, Model Context Protocol)
3. **Prompt Architectures** (`prompts/system.md`, `.prompt` templates)
4. **LangChain & LangGraph** (`Tool`, `StructuredTool`, `AgentExecutor`)
5. **LlamaIndex** (`FunctionTool`, `ReActAgent`)
6. **CrewAI** (`Agent`, `allow_delegation`)
7. **Skill Files** (`SKILL.md`, custom agent actions)
