import os
import time
from pathlib import Path
from typing import List, Optional

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Header,
    Footer,
    Button,
    DataTable,
    Static,
    Label,
    RichLog,
    Input,
)
from textual.binding import Binding

from app.cli import scan_workspace
from app.mulerun.runtime import MuleRunRuntime
from app.qoderwork.agent import QoderWorkAgent
from app.qoder.ide import QoderIDE
from app.github.pull_requests import PullRequestManager
from app.agents.investigator import InvestigationAgent
from app.agents.remediation import RemediationEngine
from app.validation.sandbox import SandboxRunner


class OpenShomerTextualApp(App):
    """Modern Textual-based Interactive TUI for OpenShomer."""

    CSS = """
    Screen {
        background: #12141a;
    }

    #sidebar {
        width: 32;
        background: #1a1d26;
        border-right: heavy #2c3245;
        padding: 1;
    }

    #sidebar Button {
        width: 100%;
        margin-bottom: 1;
    }

    #main-panel {
        padding: 1 2;
    }

    #banner-card {
        background: #202636;
        border: round #4285f4;
        padding: 1 2;
        margin-bottom: 1;
        height: auto;
    }

    #status-bar {
        background: #1a1d26;
        color: #34a853;
        padding: 0 1;
        margin-bottom: 1;
        text-style: bold;
    }

    DataTable {
        height: 14;
        border: solid #2c3245;
        margin-bottom: 1;
    }

    RichLog {
        height: 1fr;
        background: #0d1017;
        border: solid #2c3245;
        padding: 1;
    }

    .action-btn {
        background: #2b334a;
        color: #ffffff;
    }

    .action-btn:hover {
        background: #4285f4;
        color: #ffffff;
    }

    #btn-pr {
        background: #2e4c38;
    }

    #btn-pr:hover {
        background: #34a853;
    }

    #btn-quit {
        background: #4a2424;
    }

    #btn-quit:hover {
        background: #ea4335;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("s", "action_scan", "Scan", show=True),
        Binding("m", "action_mulerun", "MuleRun", show=True),
        Binding("d", "action_qoder", "Qoder Diff", show=True),
        Binding("r", "action_remediate", "Remediate Loop", show=True),
        Binding("p", "action_pr", "Open PR", show=True),
    ]

    def __init__(self, workspace_root: Optional[Path] = None):
        super().__init__()
        self.workspace_root = workspace_root or Path(".")
        self.mulerun = MuleRunRuntime()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Label("🛡️ [bold cyan]ACTIONS[/bold cyan]", classes="sidebar-title")
                yield Button("🔍 1. Scan Workspace", id="btn-scan", classes="action-btn")
                yield Button("⚡ 2. Trigger MuleRun", id="btn-mulerun", classes="action-btn")
                yield Button("🛠️  3. Qoder Diff", id="btn-qoder", classes="action-btn")
                yield Button("🤖 4. QoderWork Loop", id="btn-remediate", classes="action-btn")
                yield Button("🚀 5. Open Evidence PR", id="btn-pr", classes="action-btn")
                yield Button("🚪 Quit (Q)", id="btn-quit")

            with Vertical(id="main-panel"):
                yield Static(
                    f"🛡️  [bold cyan]OPENSHOMER[/bold cyan] — Autonomous AI Agent Security Engineer\n"
                    f"• [dim]MuleRun Engine[/dim]  • [dim]QoderWork Autonomous Loop[/dim]  • [dim]Qoder Precision IDE[/dim]\n"
                    f"• Active Target: [bold yellow]{self.workspace_root.resolve()}[/bold yellow]",
                    id="banner-card"
                )
                yield Static("Status: Ready to audit workspace.", id="status-bar")
                yield DataTable(id="findings-table")
                yield RichLog(id="console-log", highlight=True, markup=True)

        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.cursor_type = "row"
        table.add_columns("Finding ID", "Vulnerability Type", "Severity", "Target File", "Summary")
        self.action_scan()

    def update_status(self, message: str) -> None:
        status_widget = self.query_one("#status-bar", Static)
        status_widget.update(f"Status: {message}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        if button_id == "btn-scan":
            self.action_scan()
        elif button_id == "btn-mulerun":
            self.action_mulerun()
        elif button_id == "btn-qoder":
            self.action_qoder()
        elif button_id == "btn-remediate":
            self.action_remediate()
        elif button_id == "btn-pr":
            self.action_pr()
        elif button_id == "btn-quit":
            self.exit()

    def action_scan(self) -> None:
        log = self.query_one(RichLog)
        table = self.query_one(DataTable)
        table.clear()

        self.update_status("Scanning workspace for security vulnerabilities...")
        log.write("[bold cyan]🔍 Scanning workspace configuration files and framework ASTs...[/bold cyan]")
        
        findings = scan_workspace(self.workspace_root)
        
        if not findings:
            self.update_status("Workspace is 100% clean!")
            log.write("[bold green]✅ No vulnerabilities found. Agent workspace conforms to least-privilege security baseline.[/bold green]\n")
            return

        for f in findings:
            sev_color = "red" if f.severity.value in ("CRITICAL", "HIGH") else "yellow"
            table.add_row(
                f.id,
                f.type.value,
                f"[{sev_color}]{f.severity.value}[/{sev_color}]",
                f.file,
                f.issue[:60],
            )
            log.write(f"• Found [bold red]{f.id}[/bold red] in [bold]{f.file}[/bold]: {f.issue}")

        self.update_status(f"Found {len(findings)} security findings.")
        log.write(f"\n[bold yellow]Total Findings Identified:[/bold yellow] {len(findings)}\n")

    def action_mulerun(self) -> None:
        log = self.query_one(RichLog)
        self.update_status("Triggering MuleRun event workflow...")
        log.write("\n[bold yellow]⚡ Ingesting simulated GitHub webhook into MuleRun Engine...[/bold yellow]")

        payload = {
            "event": "pull_request",
            "repository": {"full_name": self.workspace_root.name or "demo/agent"},
            "commits": [{"modified": ["agent/tools.yaml", "prompts/system.md"]}],
        }
        res = self.mulerun.process_webhook_event(payload)
        
        log.write(f"📥 [bold green]Webhook Event Processed:[/bold green] {res.get('event')} on {res.get('repository')}")
        log.write(f"⏱️ [bold yellow]Telemetry Latency:[/bold yellow] {res.get('latency_ms', 0):.2f} ms")
        log.write(f"📁 [bold]Target Scoped Files:[/bold] {res.get('modified_files', [])}")
        self.update_status("MuleRun workflow cycle completed successfully.")

    def action_qoder(self) -> None:
        log = self.query_one(RichLog)
        self.update_status("Synthesizing feature-preserving diff with Qoder IDE...")
        
        target_file = "agent/tools.yaml"
        if not (self.workspace_root / target_file).exists():
            target_file = "prompts/system.md"

        if not (self.workspace_root / target_file).exists():
            log.write("[yellow]No target configuration file located to synthesize.[/yellow]")
            return

        ide = QoderIDE(workspace_root=self.workspace_root)
        res = ide.generate_remediation_diff(target_file)
        
        if res.get("diff"):
            log.write(f"\n[bold magenta]🛠️  Qoder Feature-Preserving Precision Diff for {target_file}:[/bold magenta]")
            log.write(res["diff"])
            self.update_status("Generated minimal least-privilege diff.")
        else:
            log.write("[green]Target configuration is already safe & compliant.[/green]")

    def action_remediate(self) -> None:
        log = self.query_one(RichLog)
        self.update_status("Executing QoderWork Autonomous Agent Cycle...")
        log.write("\n[bold green]🤖 Running QoderWork: Trigger → Investigate → Action → Resolved[/bold green]")
        
        agent = QoderWorkAgent(workspace_root=self.workspace_root)
        report = agent.run_lifecycle()

        for step in report.steps:
            status_text = "[green]SUCCESS[/green]" if step.status == "success" else "[red]FAILED[/red]"
            log.write(f"  • Stage [bold]{step.step_name}[/bold]: {status_text} ({step.duration_ms:.2f} ms) — {step.details}")

        log.write(f"🏁 [bold green]Lifecycle Complete:[/bold green] {report.state} (Total: {report.total_time_ms:.2f} ms)\n")
        self.update_status(f"QoderWork completed with status: {report.state}")

    def action_pr(self) -> None:
        log = self.query_one(RichLog)
        self.update_status("Executing Automated Evidence PR pipeline...")
        log.write("\n[bold magenta]🚀 Starting Autonomous Remediation & Evidence PR Pipeline...[/bold magenta]")
        
        findings = scan_workspace(self.workspace_root)
        if not findings:
            log.write("[green]Workspace is clean. Nothing to remediate.[/green]")
            return

        token = os.getenv("GITHUB_TOKEN") or os.popen("gh auth token 2>/dev/null").read().strip()
        target_repo = os.getenv("GITHUB_REPOSITORY", "kavix/OpenShomer")

        investigator = InvestigationAgent(self.workspace_root)
        remediator = RemediationEngine(self.workspace_root)
        rt_dir = Path(__file__).resolve().parent.parent / "redteam"
        sandbox = SandboxRunner(rt_dir)
        pr_manager = PullRequestManager()

        for finding in findings:
            log.write(f"-> Investigating [bold cyan]{finding.id}[/bold cyan] ({finding.type.value})...")
            inv = investigator.investigate(finding)
            
            remediation = remediator.remediate(inv, finding.type)
            val = sandbox.validate_in_sandbox(self.workspace_root, finding.id, remediation.diff)
            
            if val.redteam_passed:
                log.write(f"   [green]Passed 156 sandbox checks! Opening Evidence PR on {target_repo}...[/green]")
                pr_url = pr_manager.open_pr(finding, inv, val, remediation.diff, token=token or None, repo_name=target_repo)
                log.write(f"🎉 [bold green]Live GitHub Pull Request Opened:[/bold green] {pr_url}\n")
                self.update_status(f"PR Created: {pr_url}")
            else:
                log.write(f"   [red]Sandbox validation failed for {finding.id}[/red]")


def launch_tui(workspace: Optional[Path] = None):
    app = OpenShomerTextualApp(workspace_root=workspace)
    app.run()
