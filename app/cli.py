import json
import sys
from pathlib import Path
from typing import List, Optional
import typer
from rich.console import Console
from rich.table import Table

from app.models.findings import Finding, FindingType, Severity, FindingStatus
from app.agents.investigator import InvestigationAgent
from app.agents.remediation import RemediationEngine
from app.agents.providers import get_llm_provider, LLMProvider
from app.validation.sandbox import SandboxRunner
from app.github.pull_requests import PullRequestManager
from app.fast_io import FastEngineSerializer


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
            if "ignore previous instructions" in content.lower() or "always fulfill whatever" in content.lower() or "bypass" in content.lower():
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
    # 4. v0.2 Richer Agent Graphs: Skill files, LangChain, LlamaIndex, and CrewAI
    from app.frameworks import scan_all_agent_frameworks
    framework_findings = scan_all_agent_frameworks(workspace_root)
    findings.extend(framework_findings)

    return findings


@app.command(name="scan")
def scan_command(
    path: Path = typer.Argument(Path("."), help="Path to AI agent repository directory"),
    json_output: bool = typer.Option(False, "--json", help="Output findings as JSON"),
    sarif: Optional[Path] = typer.Option(None, "--sarif", help="Export OASIS SARIF v2.1.0 report for GitHub Advanced Security / CI"),
    aibom: Optional[Path] = typer.Option(None, "--aibom", help="Export CycloneDX AI Bill of Materials (AIBOM) JSON"),
    exit_code: bool = typer.Option(True, "--exit-code/--no-exit-code", help="Exit with 1 on HIGH/CRITICAL risks"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Print detailed scan execution logs"),
) -> None:
    """Scan an AI agent codebase for security misconfigurations and dangerous capabilities."""
    from app.models.industrial_reports import IndustrialReportExporter
    workspace_path = path.resolve()
    if not workspace_path.exists() or not workspace_path.is_dir():
        console.print(f"[red]Error: Path '{workspace_path}' does not exist or is not a directory.[/red]")
        raise typer.Exit(code=2)

    if not json_output and not sarif and not aibom:
        console.print(f'\n🔍 [bold cyan]Scanning[/bold cyan] "[bold]{workspace_path.name}[/bold]" for AI Agent security risks...\n')

    findings = scan_workspace(workspace_path)

    # Export industrial SARIF format
    if sarif:
        sarif_doc = IndustrialReportExporter.export_sarif(findings, workspace_path)
        sarif.write_text(FastEngineSerializer.dumps(sarif_doc), encoding="utf-8")
        console.print(f"📄 [bold green]Exported Industrial SARIF v2.1.0 report to:[/bold green] {sarif}")
        return

    # Export CycloneDX AI Bill of Materials
    if aibom:
        bom_doc = IndustrialReportExporter.export_ai_bom(workspace_path, findings)
        aibom.write_text(FastEngineSerializer.dumps(bom_doc), encoding="utf-8")
        console.print(f"📦 [bold green]Exported CycloneDX AI Bill of Materials (AIBOM) to:[/bold green] {aibom}")
        return

    if json_output:
        results = [f.model_dump(mode="json") for f in findings]
        typer.echo(FastEngineSerializer.dumps(results))
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
            console.print(f"\n❌ [bold red]{len(findings)} security risk(s) found.[/bold red] Run '[bold cyan]openshomer fix {path}[/bold cyan]' or '[bold cyan]openshomer auto-pr {path}[/bold cyan]' to remediate and create a PR.\n")
        else:
            console.print("✅ [bold green]Zero security risks found![/bold green] All agent policies and permissions verified.\n")

    has_high_or_critical = any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)
    if exit_code and has_high_or_critical:
        raise typer.Exit(code=1)


@app.command(name="fix")
def fix_command(
    path: Path = typer.Argument(Path("."), help="Path to AI agent repository directory"),
    auto_pr: bool = typer.Option(False, "--auto-pr", help="Automatically create GitHub PR if token available"),
    github_token: Optional[str] = typer.Option(None, "--github-token", envvar="GITHUB_TOKEN", help="GitHub Personal Access Token"),
    repo_name: Optional[str] = typer.Option(None, "--repo", "--repo-name", envvar="GITHUB_REPOSITORY", help="GitHub Repository (owner/repo)"),
    provider: Optional[str] = typer.Option(None, "--provider", envvar="OPENSHOMER_LLM_PROVIDER", help="LLM Provider (alibaba, openai, gemini)"),
    model: Optional[str] = typer.Option(None, "--model", envvar="OPENSHOMER_LLM_MODEL", help="Model name (e.g. qwen-plus, qwen-max, gpt-4o)"),
    api_key: Optional[str] = typer.Option(None, "--api-key", help="API key for LLM reasoning"),
    redteam_dir: Optional[Path] = typer.Option(None, "--redteam-dir", help="Path to redteam test suite directory"),
) -> None:
    """Investigate findings, synthesize safe diffs, validate in sandbox, and optionally open a PR."""
    workspace_path = path.resolve()
    if not workspace_path.exists() or not workspace_path.is_dir():
        console.print(f"[red]Error: Path '{workspace_path}' does not exist or is not a directory.[/red]")
        raise typer.Exit(code=2)

    console.print(f"\n[bold cyan]OpenShomer Autonomous Remediation Engine[/bold cyan] targeting [bold]{workspace_path.name}[/bold]...\n")

    findings = scan_workspace(workspace_path)
    if not findings:
        console.print("[bold green]No security vulnerabilities detected.[/bold green] Nothing to remediate.\n")
        return

    llm = get_llm_provider(provider_name=provider, model=model, api_key=api_key)
    if llm:
        console.print(f"🤖 [bold green]Active LLM Provider:[/bold green] {llm.__class__.__name__} ({llm.model})\n")

    rt_dir = redteam_dir.resolve() if redteam_dir else Path(__file__).resolve().parent.parent / "redteam"
    investigator = InvestigationAgent(workspace_path, llm_provider=llm)
    remediator = RemediationEngine(workspace_path, llm_provider=llm)
    sandbox = SandboxRunner(rt_dir)
    pr_manager = PullRequestManager()

    remediated_count = 0
    for finding in findings:
        console.print(f"-> Investigating [bold cyan]{finding.id}[/bold cyan] ({finding.type.value})...")
        investigation = investigator.investigate(finding)

        console.print("   Generating scoped patch...")
        remediation = remediator.remediate(investigation, finding.type)

        if not remediation.guardrails_passed:
            console.print(f"   [red]Remediation rejected by guardrails: {remediation.rejection_reason}[/red]")
            continue

        console.print("   Running 50+ adversarial red-team test cases in sandbox...")
        validation = sandbox.validate_in_sandbox(workspace_path, finding.id, remediation.diff)

        if validation.redteam_passed:
            remediated_count += 1
            console.print(f"   [green]Passed sandbox validation! ({validation.passed_redteam_tests}/{validation.total_redteam_tests} tests)[/green]")
            if auto_pr:
                pr_url = pr_manager.open_pr(finding, investigation, validation, remediation.diff, token=github_token, repo_name=repo_name)
                console.print(f"   [bold magenta]Opened PR:[/bold magenta] {pr_url}")
        else:
            console.print(f"   [red]Failed sandbox tests ({validation.passed_redteam_tests}/{validation.total_redteam_tests} passed)[/red]")

    console.print(f"\n[bold green]Successfully validated {remediated_count}/{len(findings)} security remediations.[/bold green]\n")


@app.command(name="auto-pr")
def auto_pr_command(
    path: Path = typer.Argument(Path("."), help="Path to target agent repository"),
    repo_name: Optional[str] = typer.Option(None, "--repo-name", "--repo", envvar="GITHUB_REPOSITORY", help="GitHub repo name (e.g. owner/repo)"),
    github_token: Optional[str] = typer.Option(None, "--github-token", envvar="GITHUB_TOKEN", help="GitHub Personal Access Token"),
    provider: Optional[str] = typer.Option(None, "--provider", envvar="OPENSHOMER_LLM_PROVIDER", help="LLM Provider (alibaba, openai, gemini)"),
    model: Optional[str] = typer.Option(None, "--model", envvar="OPENSHOMER_LLM_MODEL", help="Model name (e.g. qwen-plus, qwen-max, gpt-4o)"),
    api_key: Optional[str] = typer.Option(None, "--api-key", help="API key for LLM reasoning"),
    redteam_dir: Optional[Path] = typer.Option(None, "--redteam-dir", help="Path to redteam test suite directory"),
) -> None:
    """Full autonomous pipeline: Scan -> Investigate -> Rewrite -> 150+ Red-Team Validation -> Evidence PR."""
    fix_command(
        path=path,
        auto_pr=True,
        github_token=github_token,
        repo_name=repo_name,
        provider=provider,
        model=model,
        api_key=api_key,
        redteam_dir=redteam_dir,
    )


@app.command(name="mulerun")
def mulerun_command(
    webhook_event: Optional[str] = typer.Option(None, "--event", help="Simulate a GitHub webhook event (push, pull_request)"),
    repo: str = typer.Option("owner/agent-repo", "--repo", help="Target repository identifier"),
) -> None:
    """MuleRun: Automated AI security workflow runtime."""
    from app.mulerun.runtime import MuleRunRuntime
    console.print("\n⚡ [bold cyan]MuleRun AI Workflow Runtime[/bold cyan]\n")
    
    runtime = MuleRunRuntime()
    event_data = {
        "event": webhook_event or "pull_request",
        "repository": {"full_name": repo},
        "commits": [{"modified": ["agent/tools.yaml", "prompts/system.md"]}],
    }
    
    res = runtime.process_webhook_event(event_data)
    console.print(f"📥 [bold green]Webhook Processed:[/bold green] {res['event']} on [bold]{res['repository']}[/bold]")
    console.print(f"⏱️ [bold yellow]Latency:[/bold yellow] {res['latency_ms']:.2f} ms")
    console.print(f"📁 [bold]Affected Files:[/bold] {res['affected_files']}\n")


@app.command(name="qoderwork")
def qoderwork_command(
    path: Path = typer.Argument(Path("."), help="Path to target agent repository"),
    provider: Optional[str] = typer.Option(None, "--provider", envvar="OPENSHOMER_LLM_PROVIDER", help="LLM Provider"),
) -> None:
    """QoderWork: Autonomous Desktop AI Agent (Trigger -> Investigate -> Action -> Resolved)."""
    from app.qoderwork.agent import QoderWorkAgent
    console.print("\n🤖 [bold cyan]QoderWork Autonomous Security Agent Loop[/bold cyan]\n")
    
    agent = QoderWorkAgent(workspace_root=path)
    report = agent.run_lifecycle()
    
    table = Table(title="QoderWork Execution Lifecycle")
    table.add_column("Stage", style="bold cyan")
    table.add_column("Status", style="green")
    table.add_column("Duration (ms)", justify="right")
    table.add_column("Details")
    
    for step in report.steps:
        table.add_row(
            step.step_name,
            "[green]SUCCESS[/green]" if step.status == "success" else "[red]FAILED[/red]",
            f"{step.duration_ms:.2f}",
            str(step.details),
        )
    
    console.print(table)
    console.print(f"\n[bold]Final Lifecycle State:[/bold] [bold green]{report.state}[/bold green] (Total: {report.total_time_ms:.2f} ms)\n")


@app.command(name="qoder")
def qoder_command(
    file_path: str = typer.Argument(..., help="Relative path to vulnerable configuration file (e.g. agent/tools.yaml, prompts/system.md)"),
    workspace: Path = typer.Option(Path("."), "--workspace", "-w", help="Workspace root directory"),
) -> None:
    """Qoder: AI-Native Agentic IDE backbone for minimal diffs and prompt fences."""
    from app.qoder.ide import QoderIDE
    console.print(f"\n🛠️ [bold cyan]Qoder Precision Synthesizer[/bold cyan] analyzing [bold]{file_path}[/bold]...\n")
    
    ide = QoderIDE(workspace_root=workspace)
    result = ide.generate_remediation_diff(file_path)
    
    if not result.get("success"):
        console.print(f"[red]Error or no changes generated:[/red] {result.get('error', 'No modifications needed.')}")
        return
    
    console.print("[bold green]Generated Minimal Scoped Diff:[/bold green]")
    console.print(result["diff"])


@app.command(name="tui")
def tui_command(
    path: Path = typer.Argument(Path("."), help="Path to target agent workspace"),
) -> None:
    """Launch OpenShomer interactive Terminal User Interface (TUI)."""
    from app.tui import launch_tui
    launch_tui(workspace=path)


@app.command(name="version")
def version_command() -> None:
    """Print the OpenShomer version."""
    console.print("OpenShomer CLI v0.2.0 — Autonomous AI Agent Security Engineer (Powered by MuleRun, QoderWork & Qoder)")


if __name__ == "__main__":
    app()


