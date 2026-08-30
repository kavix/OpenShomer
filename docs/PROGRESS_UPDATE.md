# OpenShomer — Progress Update

**Issue:** [#57 — Progress update before session](https://github.com/kavix/OpenShomer/issues/57)
**Session:** August 31st, 5 PM
**Author:** @kavix

---

## TL;DR (text-message version)

> OpenShomer v0.1 core pipeline is complete and merged — scan → investigate → remediate → red-team validate → evidence PR all work end-to-end, plus a zero-config CLI, 156-case red-team suite, OWASP LLM static rules, and an official MCP server. Currently wiring up the reusable GitHub Action for automated PR scanning + remediation (#27). Main challenge: triaging a backlog of 14 open issues and keeping feature branches synced with fast-moving `main`.

---

## Current Project Status

OpenShomer is an autonomous AI-agent security engineer: it scans AI agent
configurations and system prompts for security risks, investigates findings,
rewrites them safely, proves the attack path is closed via red-teaming, and
opens an evidence-backed Pull Request.

**Overall phase:** v0.1 (MVP) core loop is complete and stable on `main`.
Active work is on CI/CD integration (GitHub Actions) and expanding the
red-team attack coverage.

## What's Completed So Far

### Core pipeline (v0.1) — merged to `main`
- **Finding ingestion API** — FastAPI service with `Finding` schema, findings
  endpoints, Docker support
- **Investigation agent** — LLM agent loop with read-only repo tools producing
  structured `InvestigationResult` output
- **Remediation engine + guardrails** — minimal safe rewrites with scope, size,
  permission-reduction, and syntax checks
- **Validation sandbox + red-teaming** — isolated diff runner with adversarial
  prompt-injection and tool-abuse test suites
- **GitHub PR automation** — branch/commit/PR creation with full evidence report

### Recent feature merges
| PR | Feature |
|---|---|
| #53 | Reusable composite GitHub Action (`action.yml`) & automated CI/CD evidence PR remediation |
| #52 | Adversarial attack suite expanded with granular categories & enhanced boundary validation |
| #54 | Official MCP server — use OpenShomer from Claude Desktop, Cursor, Windsurf |
| #56 | Red-team suites expanded to 156 cases, sandbox diff runner, scan-to-PR CLI |
| #51 | Zero-config CLI scanner for agent configs and system prompts |
| #55 | OWASP LLM Top-10 static analysis rules |
| #50/#48/#46 | Docs, README structure, env-key alignment, in-repo wiki |

### Tooling, Providers & Community
- **Alibaba Cloud Model Studio (Qwen)** reasoning backbone integration (`qwen-max`, `qwen-plus`, `qwen-turbo`)
- `uv` adopted as the default package manager
- GitHub Actions bots: `/assign`, LGTM auto-merge, project-board automation
- Vulnerable demo agent fixture (`demo/vulnerable-agent`) for end-to-end testing

## Current Focus & Next Steps

1. **Alibaba Cloud Model Studio / Qwen** deployment and multi-turn adversarial red-teaming benchmarks
2. Begin v0.2 planning: LangChain / CrewAI / LlamaIndex / skill-file AST scanning
3. Runtime MCP security proxy sidecar integration

## Challenges & Support Needed

1. **Issue backlog** — 14 open issues and 2 open PRs need triage/labels;
   help prioritizing for v0.2 (richer agent graphs: LangChain/LlamaIndex)
   would be valuable.
2. **Branch hygiene** — `main` is moving fast; feature branches need frequent
   rebases to avoid drift (handled for #27 today).
3. **End-to-end validation** — full agent runs depend on LLM provider API
   keys; contributors testing the pipeline need clear key setup guidance.
4. **Reviewers** — additional code review capacity on the Actions integration
   PR would help unblock the CI/CD milestone.

## Next Steps

1. Merge #27 (GitHub Action) and #26 (attack suite expansion)
2. Cut v0.1 release after Actions integration lands
3. Begin v0.2 planning: LangChain/LlamaIndex/skill-file support
