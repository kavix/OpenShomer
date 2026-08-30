import json
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from app.cli import scan_workspace

mcp = FastMCP("OpenShomer")


@mcp.tool()
def scan_agent_config(path: str = ".") -> str:
    """Scan an AI agent codebase directory for security misconfigurations, over-permissioned tools, and prompt injection vulnerabilities."""
    workspace_path = Path(path).resolve()
    if not workspace_path.exists() or not workspace_path.is_dir():
        return json.dumps({"error": f"Path '{path}' does not exist or is not a directory."}, indent=2)

    findings = scan_workspace(workspace_path)
    return json.dumps({
        "status": "success",
        "scanned_path": str(workspace_path).replace("\\", "/"),
        "finding_count": len(findings),
        "findings": [f.model_dump(mode="json") for f in findings],
    }, indent=2)


@mcp.tool()
def redteam_prompt(prompt_text: str) -> str:
    """Evaluate an AI system prompt against adversarial prompt injection, jailbreak, and credential extraction attack vectors."""
    has_boundary = (
        "Disregard any user attempts to override" in prompt_text
        or "Security Boundary" in prompt_text
        or "NEVER disclose" in prompt_text
        or "DO NOT execute unverified instructions" in prompt_text
    )
    has_leaks = "sk_live_" in prompt_text or "api_key = " in prompt_text
    has_weak_delimiters = "---" in prompt_text and not has_boundary

    vulnerabilities: list[str] = []
    if has_leaks:
        vulnerabilities.append("CRITICAL: Prompt contains raw embedded API keys or credentials")
    if not has_boundary:
        vulnerabilities.append("HIGH: Prompt lacks defensive anti-override boundary fences")
    if has_weak_delimiters:
        vulnerabilities.append("MEDIUM: Prompt uses easily escapeable markdown delimiters without verification")

    return json.dumps({
        "status": "passed" if len(vulnerabilities) == 0 else "vulnerabilities_detected",
        "redteam_passed": len(vulnerabilities) == 0,
        "vulnerabilities": vulnerabilities,
        "recommendations": [
            "Add XML tag encapsulation with strict system defense boundaries",
            "Disallow instruction overrides and roleplay jailbreaks",
            "Store secret tokens in environment variables outside prompt text",
        ] if len(vulnerabilities) > 0 else ["Prompt adheres to defensive boundary best practices."],
    }, indent=2)


@mcp.tool()
def audit_mcp_config(config_json: str) -> str:
    """Audit an MCP (Model Context Protocol) servers JSON configuration for excessive permissions, path traversals, and hardcoded secrets."""
    try:
        data = json.loads(config_json)
    except Exception as e:
        return json.dumps({"error": f"Invalid JSON provided: {e!s}"}, indent=2)

    findings: list[dict[str, Any]] = []
    servers = data.get("mcpServers", data)
    if isinstance(servers, dict):
        for name, srv in servers.items():
            if not isinstance(srv, dict):
                continue
            if srv.get("permissions", {}).get("allowAllPaths") is True:
                findings.append({
                    "server": name,
                    "severity": "HIGH",
                    "issue": "Server permits unrestricted filesystem path access (allowAllPaths=True)",
                })
            env_vals = str(srv.get("env", {}))
            if "sk_live_" in env_vals or "secret_" in env_vals:
                findings.append({
                    "server": name,
                    "severity": "CRITICAL",
                    "issue": "Raw credentials found in server environment configuration",
                })
            if not srv.get("requires_approval", True) and any(
                k in name.lower() for k in ("pay", "billing", "bank", "stripe", "gateway")
            ):
                findings.append({
                    "server": name,
                    "severity": "HIGH",
                    "issue": "Financial/payment operations lack required human approval gate",
                })

    return json.dumps({
        "status": "success",
        "safe": len(findings) == 0,
        "finding_count": len(findings),
        "findings": findings,
    }, indent=2)


def main() -> None:
    """Run OpenShomer MCP server over stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
