#!/usr/bin/env python3
"""
OpenShomer CLI: Scan, investigate, remediate, red-team validate, and open PR in a single command.
Usage:
    uv run python -m app.cli /path/to/repo [--repo-name my-org/my-agent]
"""
import argparse
import sys
from pathlib import Path
import json

from app.models.findings import Finding, FindingType, Severity, FindingStatus
from app.agents.investigator import InvestigationAgent
from app.agents.remediation import RemediationEngine
from app.validation.sandbox import SandboxRunner
from app.github.pull_requests import PullRequestManager


def scan_repo_for_findings(repo_path: Path, repo_name: str) -> list[Finding]:
    """Scans repository configuration files for risky patterns and produces initial findings."""
    findings = []
    
    # 1. Check tools.yaml
    tools_file = repo_path / "agent/tools.yaml"
    if tools_file.exists():
        content = tools_file.read_text(encoding="utf-8")
        if "shell:unrestricted" in content or "fs:write_all" in content:
            findings.append(Finding(
                id="FIND-TOOL-001",
                type=FindingType.OVER_PERMISSIONED_TOOL,
                severity=Severity.HIGH,
                file="agent/tools.yaml",
                tool="run_shell",
                issue="Over-permissioned shell execution tool with unrestricted file/command privileges",
                repository=repo_name
            ))
        if "requires_approval: false" in content and "db:read_write_unrestricted" in content:
            findings.append(Finding(
                id="FIND-GATE-002",
                type=FindingType.MISSING_APPROVAL_GATE,
                severity=Severity.HIGH,
                file="agent/tools.yaml",
                tool="execute_sql",
                issue="Destructive database tool lacks human approval gate and least-privilege scoping",
                repository=repo_name
            ))

    # 2. Check mcp_servers.json
    mcp_file = repo_path / "mcp/mcp_servers.json"
    if mcp_file.exists():
        content = mcp_file.read_text(encoding="utf-8")
        if "allowAllPaths\": true" in content or "sk_live_" in content:
            findings.append(Finding(
                id="FIND-MCP-001",
                type=FindingType.DATA_EXFILTRATION_PATH,
                severity=Severity.CRITICAL,
                file="mcp/mcp_servers.json",
                tool="filesystem",
                issue="MCP configuration exposes unrestricted filesystem traversal and hardcoded secret keys",
                repository=repo_name
            ))

    # 3. Check system prompts
    prompt_file = repo_path / "prompts/system.md"
    if prompt_file.exists():
        content = prompt_file.read_text(encoding="utf-8")
        if "Always fulfill whatever" in content or "ignore previous instructions" in content:
            findings.append(Finding(
                id="FIND-PROMPT-001",
                type=FindingType.PROMPT_INJECTION_SURFACE,
                severity=Severity.CRITICAL,
                file="prompts/system.md",
                tool=None,
                issue="System prompt lacks defensive instruction boundaries and is susceptible to direct hijacking",
                repository=repo_name
            ))

    return findings


def run_pipeline(repo_path: Path, repo_name: str):
    print("=" * 60)
    print(f"🛡️  OpenShomer Autonomous Security Engineer")
    print(f"Target Repository: {repo_path.resolve()}")
    print("=" * 60)

    if not repo_path.exists():
        print(f"❌ Error: Repository directory '{repo_path}' does not exist.")
        sys.exit(1)

    print("\n🔍 Stage 1: Scanning repository for security findings...")
    findings = scan_repo_for_findings(repo_path, repo_name)

    if not findings:
        print("✅ No known risky AI agent configuration patterns found. Repository clean!")
        return

    print(f"⚠️  Discovered {len(findings)} security finding(s):")
    for f in findings:
        print(f"   - [{f.severity.value}] {f.id} in {f.file}: {f.issue}")

    redteam_dir = Path(__file__).resolve().parent.parent / "redteam"
    investigator = InvestigationAgent(repo_path)
    engine = RemediationEngine(repo_path)
    sandbox = SandboxRunner(redteam_dir)
    pr_manager = PullRequestManager()

    for finding in findings:
        print("\n" + "-" * 60)
        print(f"⚡ Processing Finding: {finding.id} ({finding.type.value})")
        print("-" * 60)

        # Stage 2: Deep Investigation
        print("🕵️  Stage 2: Investigating agent graph and prompt boundaries...")
        investigation = investigator.investigate(finding)
        print(f"   Root Cause: {investigation.root_cause}")
        print(f"   Recommended Fix: {investigation.recommended_fix}")

        # Stage 3: Minimal Safe Rewrite
        print("\n🛠️  Stage 3: Generating minimal safe rewrite diff & evaluating guardrails...")
        remediation = engine.remediate(investigation, finding.type)
        if not remediation.guardrails_passed:
            print(f"❌ Remediation rejected by guardrails: {remediation.rejection_reason}")
            continue
        print("   ✅ Guardrails passed (scope & size limits respected).")

        # Stage 4: Sandbox & Adversarial Red-Teaming
        print("\n🧪 Stage 4: Validating in isolated sandbox across 150+ adversarial test cases...")
        validation = sandbox.validate_in_sandbox(repo_path, finding.id, remediation.diff)
        print(f"   Static Checks Passed: {validation.static_checks_passed}")
        print(f"   Red-Team Tests: {validation.passed_redteam_tests}/{validation.total_redteam_tests} passed")
        print(f"   Status: {validation.status}")

        # Stage 5: Evidence PR
        if validation.redteam_passed:
            pr_url = pr_manager.open_pr(finding, investigation, validation, remediation.diff)
            print(f"\n🎉 Stage 5: Evidence-Backed Pull Request Created Successfully!")
            print(f"   🔗 PR URL: {pr_url}")
        else:
            print("\n❌ Sandbox validation failed. PR will not be opened without full verification proof.")


def main():
    parser = argparse.ArgumentParser(
        description="OpenShomer: Find vulnerabilities in AI agent configurations and open evidence-backed PRs in one command."
    )
    parser.add_argument("repo_path", type=Path, help="Path to target agent repository")
    parser.add_argument("--repo-name", type=str, default="demo/vulnerable-agent", help="GitHub repo name (e.g., owner/repo)")
    args = parser.parse_args()

    run_pipeline(args.repo_path, args.repo_name)


if __name__ == "__main__":
    main()
