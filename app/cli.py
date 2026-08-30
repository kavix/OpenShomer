import json
import sys
from pathlib import Path
from typing import List, Optional
import typer
from rich.console import Console
from rich.table import Table
from app.models.findings import Finding, FindingType, Severity
from app.validation.static import StaticPolicyChecker

app = typer.Typer(
    name="openshomer",
    help="OpenShomer — Autonomous AI Agent Security Engineer CLI",
    add_completion=False,
)
console = Console()


def scan_workspace(workspace_root: Path) -> List[Finding]:
    """Scan an AI agent repository for configuration risks and prompt vulnerabilities."""
    findings: List[Finding] = []
    finding_idx = 1

    # 1. Check tools.yaml
    tools_file = workspace_root / "agent/tools.yaml"
    if tools_file.exists():
        import yaml
        try:
            data = yaml.safe_load(tools_file.read_text(encoding="utf-8")) or {}
            for tool in data.get("tools", []):
                tool_name = tool.get("name", "unknown")
                perms = tool.get("permissions", [])
                if "shell:unrestricted" in perms:
                    findings.append(
                        Finding(
                            id=f"SHOMER-{finding_idx:03d}",
                            type=FindingType.OVER_PERMISSIONED_TOOL,
                            severity=Severity.HIGH,
                            file="agent/tools.yaml",
                            tool=tool_name,
                            issue=f"{tool_name} has unrestricted shell scope (shell:unrestricted)",
                            repository=workspace_root.name,
                        )
                    )
                    finding_idx += 1
                if not tool.get("requires_approval", False) and "shell" in tool_name:
                    findings.append(
                        Finding(
                            id=f"SHOMER-{finding_idx:03d}",
                            type=FindingType.MISSING_APPROVAL_GATE,
                            severity=Severity.HIGH,
                            file="agent/tools.yaml",
                            tool=tool_name,
                            issue=f"{tool_name} lacks human-in-the-loop approval (requires_approval=True)",
                            repository=workspace_root.name,
                        )
                    )
                    finding_idx += 1
        except Exception as e:
            findings.append(
                Finding(
                    id=f"SHOMER-{finding_idx:03d}",
                    type=FindingType.OVER_PERMISSIONED_TOOL,
                    severity=Severity.MEDIUM,
                    file="agent/tools.yaml",
                    issue=f"Failed to parse agent/tools.yaml: {str(e)}",
                    repository=workspace_root.name,
                )
            )
            finding_idx += 1

    # 2. Check mcp_servers.json
    mcp_file = workspace_root / "mcp/mcp_servers.json"
    if mcp_file.exists():
        try:
            data = json.loads(mcp_file.read_text(encoding="utf-8"))
            for name, srv in data.get("mcpServers", {}).items():
                if srv.get("permissions", {}).get("allowAllPaths") is True:
                    findings.append(
                        Finding(
                            id=f"SHOMER-{finding_idx:03d}",
                            type=FindingType.OVER_PERMISSIONED_TOOL,
                            severity=Severity.HIGH,
                            file="mcp/mcp_servers.json",
                            tool=name,
                            issue=f"MCP server '{name}' allows unrestricted filesystem access (allowAllPaths=True)",
                            repository=workspace_root.name,
                        )
                    )
                    finding_idx += 1
                env_vals = str(srv.get("env", {}))
                if "sk_live_" in env_vals or "secret_" in env_vals:
                    findings.append(
                        Finding(
                            id=f"SHOMER-{finding_idx:03d}",
                            type=FindingType.HARDCODED_SECRET_IN_PROMPT,
                            severity=Severity.CRITICAL,
                            file="mcp/mcp_servers.json",
                            tool=name,
                            issue=f"MCP server '{name}' contains raw hardcoded secret tokens in environment",
                            repository=workspace_root.name,
                        )
                    )
                    finding_idx += 1
                if not srv.get("requires_approval", True) and any(
                    k in name.lower() for k in ("pay", "billing", "bank", "stripe", "gateway")
                ):
                    findings.append(
                        Finding(
                            id=f"SHOMER-{finding_idx:03d}",
                            type=FindingType.MISSING_APPROVAL_GATE,
                            severity=Severity.HIGH,
                            file="mcp/mcp_servers.json",
                            tool=name,
                            issue=f"Financial/payment MCP server '{name}' lacks human approval gate",
                            repository=workspace_root.name,
                        )
                    )
                    finding_idx += 1
        except Exception as e:
            findings.append(
                Finding(
                    id=f"SHOMER-{finding_idx:03d}",
                    type=FindingType.OVER_PERMISSIONED_TOOL,
                    severity=Severity.MEDIUM,
                    file="mcp/mcp_servers.json",
                    issue=f"Failed to parse mcp/mcp_servers.json: {str(e)}",
                    repository=workspace_root.name,
                )
            )
            finding_idx += 1

    # 3. Check system prompts for prompt injection surfaces and hardcoded secrets
    for prompt_path in [
        workspace_root / "prompts/system.md",
        workspace_root / "prompts/system.prompt",
        workspace_root / "system.prompt",
    ]:
        if prompt_path.exists():
            content = prompt_path.read_text(encoding="utf-8")
            rel_path = str(prompt_path.relative_to(workspace_root)).replace("\\", "/")
            if "sk_live_" in content or "api_key = " in content:
                findings.append(
                    Finding(
                        id=f"SHOMER-{finding_idx:03d}",
                        type=FindingType.HARDCODED_SECRET_IN_PROMPT,
                        severity=Severity.CRITICAL,
                        file=rel_path,
                        issue="System prompt contains hardcoded API key or credential",
                        repository=workspace_root.name,
                    )
                )
                finding_idx += 1
            if "ignore previous instructions" in content.lower() or "bypass" in content.lower():
                findings.append(
                    Finding(
                        id=f"SHOMER-{finding_idx:03d}",
                        type=FindingType.PROMPT_INJECTION_SURFACE,
                        severity=Severity.HIGH,
                        file=rel_path,
                        issue="System prompt contains vulnerable bypass or instruction override phrases",
                        repository=workspace_root.name,
                    )
                )
                finding_idx += 1

    return findings


@app.command(name="scan")
def scan_command(
    path: Path = typer.Argument(Path("."), help="Path to AI agent repository directory"),
    json_output: bool = typer.Option(False, "--json", help="Output findings as JSON"),
    exit_code: bool = typer.Option(True, "--exit-code/--no-exit-code", help="Exit with 1 on HIGH/CRITICAL risks"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Print detailed scan execution logs"),
) -> None:
    """Scan an AI agent codebase for security misconfigurations and dangerous capabilities."""
    workspace_path = path.resolve()
    if not workspace_path.exists() or not workspace_path.is_dir():
        console.print(f"[red]Error: Path '{workspace_path}' does not exist or is not a directory.[/red]")
        raise typer.Exit(code=2)

    if not json_output:
        console.print(f'\n🔍 [bold cyan]Scanning[/bold cyan] "[bold]{workspace_path.name}[/bold]" for AI Agent security risks...\n')

    findings = scan_workspace(workspace_path)

    if json_output:
        results = [f.model_dump(mode="json") for f in findings]
        typer.echo(json.dumps(results, indent=2))
    else:
        if findings:
            table = Table(title="OpenShomer Security Findings", show_header=True, header_style="bold magenta")
            table.add_column("Finding ID", style="cyan", width=12)
            table.add_column("Type", style="white", width=26)
            table.add_column("Severity", justify="center", width=10)
            table.add_column("File", style="dim", width=22)
            table.add_column("Issue Summary", style="yellow")

            for f in findings:
                sev_color = "red" if f.severity in (Severity.HIGH, Severity.CRITICAL) else "yellow"
                table.add_row(
                    f.id,
                    f.type.value,
                    f"[{sev_color}]{f.severity.value}[/{sev_color}]",
                    f.file,
                    f.issue,
                )
            console.print(table)
            console.print(f"\n❌ [bold red]{len(findings)} security risk(s) found.[/bold red] Run '[bold cyan]openshomer fix {path}[/bold cyan]' to generate an evidence-backed patch.\n")
        else:
            console.print("✅ [bold green]Zero security risks found![/bold green] All agent policies and permissions verified.\n")

    has_high_or_critical = any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)
    if exit_code and has_high_or_critical:
        raise typer.Exit(code=1)


@app.command(name="version")
def version_command() -> None:
    """Print the OpenShomer version."""
    console.print("OpenShomer CLI v0.1.0 — Autonomous AI Agent Security Engineer")


if __name__ == "__main__":
    app()
