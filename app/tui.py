import sys
import time
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.prompt import Prompt
from rich.syntax import Syntax
from rich.text import Text

from app.cli import scan_workspace
from app.mulerun.runtime import MuleRunRuntime
from app.qoderwork.agent import QoderWorkAgent
from app.qoder.ide import QoderIDE


class OpenShomerTUI:
    """Interactive Terminal User Interface (TUI) for OpenShomer."""

    def __init__(self, workspace_root: Optional[Path] = None):
        self.console = Console()
        self.workspace_root = workspace_root or Path(".")
        self.mulerun = MuleRunRuntime()

    def display_banner(self):
        banner_text = Text()
        banner_text.append("🛡️  OPENSHOMER ", style="bold cyan")
        banner_text.append("— Autonomous AI Agent Security Engineer\n", style="bold white")
        banner_text.append("   • Runtime: ", style="dim")
        banner_text.append("MuleRun (<100ms)  ", style="bold yellow")
        banner_text.append("• Autonomous Loop: ", style="dim")
        banner_text.append("QoderWork  ", style="bold green")
        banner_text.append("• Precision IDE: ", style="dim")
        banner_text.append("Qoder\n", style="bold magenta")
        banner_text.append(f"   • Active Workspace: {self.workspace_root.resolve()}", style="dim")

        self.console.print(Panel(banner_text, border_style="cyan", padding=(1, 2)))

    def run_scan_view(self):
        self.console.print("\n[bold cyan]🔍 Scanning Workspace for Security Misconfigurations...[/bold cyan]\n")
        findings = scan_workspace(self.workspace_root)
        
        if not findings:
            self.console.print(Panel("✅ [bold green]Workspace Clean![/bold green] No security vulnerabilities detected in system prompts, tools, or MCP configs.", border_style="green"))
            return

        table = Table(title=f"Security Findings ({len(findings)} detected)", border_style="red")
        table.add_column("ID", style="bold cyan", width=12)
        table.add_column("Type", style="magenta")
        table.add_column("Severity", style="bold red")
        table.add_column("File", style="yellow")
        table.add_column("Issue Summary")

        for f in findings:
            sev_style = "bold red" if f.severity.value in ("CRITICAL", "HIGH") else "yellow"
            table.add_row(
                f.id,
                f.type.value,
                f"[{sev_style}]{f.severity.value}[/{sev_style}]",
                f.file,
                f.issue[:65] + ("..." if len(f.issue) > 65 else ""),
            )

        self.console.print(table)
        self.console.print("")

    def run_mulerun_view(self):
        self.console.print("\n[bold yellow]⚡ MuleRun Low-Latency Event Workflow Test[/bold yellow]\n")
        
        start_time = time.time()
        payload = {
            "event": "pull_request",
            "repository": {"full_name": self.workspace_root.name or "demo/agent"},
            "commits": [{"modified": ["agent/tools.yaml", "prompts/system.md"]}],
        }
        res = self.mulerun.process_webhook_event(payload)
        
        info = (
            f"• [bold green]Webhook Event Processed:[/bold green] {res['event']}\n"
            f"• [bold yellow]Pipeline Latency:[/bold yellow] {res['latency_ms']:.2f} ms ([green]< 100 ms target met[/green])\n"
            f"• [bold]Affected Target Files:[/bold] {res['modified_files']}\n"
            f"• [bold]Live Telemetry Events Count:[/bold] {len(self.mulerun.telemetry_history)}"
        )
        self.console.print(Panel(info, title="MuleRun Runtime Telemetry", border_style="yellow"))

    def run_qoder_view(self):
        self.console.print("\n[bold magenta]🛠️  Qoder Precision Diff & Defense Synthesizer[/bold magenta]\n")
        
        target_file = "agent/tools.yaml"
        if not (self.workspace_root / target_file).exists():
            target_file = "prompts/system.md"
        
        if not (self.workspace_root / target_file).exists():
            self.console.print("[yellow]No target tools.yaml or system.md found in workspace to synthesize.[/yellow]")
            return

        ide = QoderIDE(workspace_root=self.workspace_root)
        res = ide.generate_remediation_diff(target_file)
        
        if res.get("diff"):
            syntax = Syntax(res["diff"], "diff", theme="monokai", line_numbers=True)
            self.console.print(Panel(syntax, title=f"Feature-Preserving Diff: {target_file}", border_style="magenta"))
        else:
            self.console.print("[green]Target file is already safe & compliant.[/green]")

    def run_qoderwork_autonomous_loop(self):
        self.console.print("\n[bold green]🤖 QoderWork Autonomous Agent Cycle: Trigger → Investigate → Action → Resolved[/bold green]\n")
        agent = QoderWorkAgent(workspace_root=self.workspace_root)
        
        with self.console.status("[bold green]Executing autonomous remediation loop & 156 red-team checks...[/bold green]"):
            report = agent.run_lifecycle()

        table = Table(title="QoderWork Execution Lifecycle", border_style="green")
        table.add_column("Stage", style="bold cyan")
        table.add_column("Status", style="bold green")
        table.add_column("Duration (ms)", justify="right")
        table.add_column("Details")

        for step in report.steps:
            st_color = "green" if step.status == "success" else "red"
            table.add_row(
                step.step_name,
                f"[{st_color}]{step.status.upper()}[/{st_color}]",
                f"{step.duration_ms:.2f}",
                str(step.details),
            )

        self.console.print(table)
        self.console.print(f"\n[bold]Final Status:[/bold] [bold green]{report.state}[/bold green] (Total Execution: {report.total_time_ms:.2f} ms)\n")

    def start_interactive_menu(self):
        while True:
            self.console.clear()
            self.display_banner()
            
            self.console.print("[bold]Select an action:[/bold]")
            self.console.print("  [bold cyan]1.[/bold cyan] 🔍 Scan Workspace for Security Vulnerabilities")
            self.console.print("  [bold yellow]2.[/bold yellow] ⚡ Trigger MuleRun Low-Latency Ingress (<100ms)")
            self.console.print("  [bold magenta]3.[/bold magenta] 🛠️  Synthesize Qoder Precision Diffs & Fences")
            self.console.print("  [bold green]4.[/bold green] 🤖 Run QoderWork Full Autonomous Security Loop")
            self.console.print("  [bold red]5.[/bold red] 🚪 Exit TUI\n")

            choice = Prompt.ask("[bold]Enter choice (1-5)[/bold]", choices=["1", "2", "3", "4", "5"], default="1")

            if choice == "1":
                self.run_scan_view()
            elif choice == "2":
                self.run_mulerun_view()
            elif choice == "3":
                self.run_qoder_view()
            elif choice == "4":
                self.run_qoderwork_autonomous_loop()
            elif choice == "5":
                self.console.print("\n[bold cyan]Goodbye from OpenShomer![/bold cyan]\n")
                break

            Prompt.ask("\n[dim]Press Enter to return to main menu...[/dim]")


def launch_tui(workspace: Optional[Path] = None):
    tui = OpenShomerTUI(workspace_root=workspace)
    tui.start_interactive_menu()
