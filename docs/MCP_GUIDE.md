# OpenShomer Model Context Protocol (MCP) Server Guide

OpenShomer provides a native [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server built on FastMCP. It exposes real-time security scanning, adversarial red-teaming, and configuration auditing capabilities directly to AI desktop assistants, coding IDEs, and autonomous agents.

---

## 1. Quick Installation via Smithery

If you use Smithery, you can install OpenShomer directly with one command:

### For Claude Desktop
```bash
npx -y @smithery/cli install @kavix/OpenShomer --client claude
```

### For Cursor
```bash
npx -y @smithery/cli install @kavix/OpenShomer --client cursor
```

---

## 2. Manual Client Configurations

### A. Claude Desktop

Add the following to your `claude_desktop_config.json`:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

#### Option 1: Using `uvx` (Zero-install Python runtime)

```json
{
  "mcpServers": {
    "openshomer": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/kavix/OpenShomer.git",
        "openshomer-mcp"
      ]
    }
  }
}
```

#### Option 2: Using Docker (GitHub Container Registry)

```json
{
  "mcpServers": {
    "openshomer": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "ghcr.io/kavix/openshomer:latest",
        "mcp"
      ]
    }
  }
}
```

---

### B. Cursor

In Cursor, open **Settings -> Features -> MCP Servers**, click **Add New MCP Server**, or add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "openshomer": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/kavix/OpenShomer.git",
        "openshomer-mcp"
      ]
    }
  }
}
```

---

### C. Claude Code CLI

Add OpenShomer directly to your Claude Code configuration:

```bash
claude mcp add openshomer -- uvx --from git+https://github.com/kavix/OpenShomer.git openshomer-mcp
```

Or using Docker:

```bash
claude mcp add openshomer -- docker run -i --rm ghcr.io/kavix/openshomer:latest mcp
```

---

### D. Windsurf / Codeium

Add to `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "openshomer": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/kavix/OpenShomer.git",
        "openshomer-mcp"
      ]
    }
  }
}
```

---

## 3. Exposed MCP Tools

Once connected, your AI assistant gains access to the following 3 security tools:

### `scan_agent_config`
Scans an AI agent repository for framework misconfigurations, over-privileged tools, unvetted code execution sinks, and prompt injection vulnerabilities.

- **Parameters**:
  - `path` *(string, optional, default: `.`)*: Directory path of the agent workspace to audit.
- **Example Assistant Query**:
  > "Please use OpenShomer's `scan_agent_config` to audit the security posture of this project."

---

### `redteam_prompt`
Evaluates an AI system prompt against adversarial prompt injection, jailbreak delimiters, role-play overrides, and credential extraction vectors.

- **Parameters**:
  - `prompt_text` *(string, required)*: The raw system prompt text to evaluate.
- **Example Assistant Query**:
  > "Evaluate this system prompt with `redteam_prompt` to check if it lacks defensive boundary fences."

---

### `audit_mcp_config`
Audits an MCP server JSON configuration for critical security issues such as unrestricted filesystem access (`allowAllPaths=True`), raw credentials in environment variables, and missing human approval gates for high-impact operations.

- **Parameters**:
  - `config_json` *(string, required)*: MCP server configuration JSON string.
- **Example Assistant Query**:
  > "Run `audit_mcp_config` on my current MCP configuration to see if any tools expose dangerous host permissions."

---

## 4. Local Testing & Verification

To verify the MCP server directly over standard I/O:

```bash
# Clone the repository
git clone https://github.com/kavix/OpenShomer.git
cd OpenShomer

# Run the MCP server directly
uv run openshomer-mcp
```

You can inspect the tools using the official MCP Inspector:

```bash
npx @modelcontextprotocol/inspector uv run openshomer-mcp
```
