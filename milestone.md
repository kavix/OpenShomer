# OpenShomer — Milestones & Build Guide

This is the working README for the project board. It answers three things for every phase: **what gets added**, **how you add it**, and **how you know it's done**.

---

## How a milestone is defined here

A milestone in this project is **not** "a bunch of related tasks." It's one specific rule, repeated every time:

> **One milestone = one new capability that works end-to-end on its own, proven by a single command or test run — not a pile of half-built pieces.**

Practically, that means every milestone below has the same four parts:

| Part | What it means |
|---|---|
| **What you add** | The exact files/modules that get created — maps 1:1 to a "cell" from the architecture doc |
| **How** | The concrete steps, in order, to build it |
| **Definition of Done (DoD)** | A command, test, or demo that either passes or doesn't — no judgment calls |
| **GitHub mapping** | 1 milestone = 1 GitHub Milestone; each numbered step below = 1 Issue, labelled `phase:N` + a cell label (`cell:api`, `cell:agent`, `cell:validation`, `cell:git`) |

If a step can't be checked off by running something, it isn't done yet — "looks right" doesn't count.

---

## Phase 0 — Demo Repo *(prerequisite, not a code milestone)*

**What you add:** a separate throwaway repo, `demo-app/`, *not* inside `open-shomer` itself.

```
demo-app/
├── package.json          ← pin a real vulnerable version, e.g. "lodash": "4.17.20"
├── package-lock.json
├── src/
│   ├── app.js             ← must actually `require('lodash')`, not just declare it
│   └── payment.js
└── tests/
    └── payment.test.js    ← trivial, but must pass today
```

**How:**
1. `npm init -y` in a new folder, `npm install lodash@4.17.20`
2. Write one function in `src/payment.js` that actually calls a lodash method
3. Write one Jest/Mocha test that exercises it
4. Push to its own GitHub repo (e.g. `<you>/demo-app`) — this is the target OpenShomer will operate on, kept separate so you never confuse "the tool" with "the thing being fixed"

**Definition of Done:** `npm install && npm test` passes, and `npm audit` (or checking OSV.dev directly) shows the lodash version as vulnerable.

**GitHub mapping:** no code milestone — just an issue "Create demo-app fixture" closed when the repo exists.

---

## Phase 1 — Finding Ingestion API ✅ *(already built)*

**What you add:**
```
app/models.py     ← Finding, FindingType, Severity, FindingReceipt (Pydantic)
app/main.py       ← POST /findings, GET /findings/{id}, GET /findings, GET /health
tests/test_findings.py
requirements.txt  ← fastapi, uvicorn, pydantic, pytest, httpx
Dockerfile
docker-compose.yml
.env.example
```

**How:**
1. Define the finding schema in `app/models.py` as a Pydantic model — this is the contract every later phase validates against, so lock it down early
2. Stand up a FastAPI app in `app/main.py` with an in-memory `dict` store (don't design a database yet)
3. Write a `pytest` test that posts a finding and reads it back — this *is* the spec, not an afterthought
4. Containerize with a minimal `Dockerfile` + `docker-compose.yml` so Phase 4's sandbox has a consistent pattern to copy later

**Definition of Done:** `pytest -q` passes; `curl -X POST localhost:8000/findings -d @finding.json` returns `{"status": "received", ...}` and `GET /findings/F-001` returns it back.

**GitHub mapping:** Milestone "v0.1 — Phase 1: Ingestion". Issues: `Define Finding schema`, `Build POST/GET /findings`, `Write ingestion tests`, `Dockerize API`.

---

## Phase 2 — Investigation Agent

**What you add:**
```
app/agents/__init__.py
app/agents/tools.py          ← read_file(), search_code(), get_dependencies(), get_git_history(), list_files() — operating on a cloned repo, nothing else
app/agents/schemas.py        ← InvestigationResult (Pydantic): root_cause, affected_files, recommended_fix, confidence, risk
app/agents/investigator.py   ← calls Anthropic's tool-use API, forces structured output against InvestigationResult
requirements.txt             ← + anthropic, gitpython
app/main.py                  ← + POST /findings/{id}/investigate
```

**How:**
1. Write `tools.py` first, as plain functions with no LLM involved — test them directly against a `git clone` of `demo-app` before any agent code touches them. This is your whitelist; the agent gets nothing else.
2. Define `InvestigationResult` in `schemas.py` — the exact shape you want back, no free text fields.
3. In `investigator.py`, call the model with `tools=[...]` (Anthropic tool-use / function calling), loop while it requests tool calls, and on its final answer, **validate against `InvestigationResult` before returning it**. If validation fails, retry once with an error message appended, then fail loudly — never pass unvalidated output downstream.
4. Wire `POST /findings/{id}/investigate` in `main.py`: look up the stored finding, clone its `repository`, run the investigator, store and return the result.

**Definition of Done:** calling `POST /findings/F-001/investigate` against the real `demo-app` returns a schema-valid JSON body whose `root_cause` correctly names lodash, without any human editing the output.

**GitHub mapping:** Milestone "v0.1 — Phase 2: Investigation". Issues: `Repo tool belt`, `InvestigationResult schema`, `Investigator agent loop`, `/investigate endpoint`, `Test against demo-app`.

---

## Phase 3 — Remediation Engine + Patch Guardrails

**What you add:**
```
app/agents/remediation.py     ← takes InvestigationResult, produces a git diff limited to affected_files
app/validation/__init__.py
app/validation/guardrails.py  ← scope check, size check, relevance check, lockfile-consistency check
app/main.py                   ← + POST /findings/{id}/remediate
```

**How:**
1. `remediation.py` prompts the model with an explicit instruction to touch only `affected_files` from the investigation result, then captures the result as an actual `git diff` (via `gitpython`), never as "trust me, files were edited."
2. `guardrails.py` is plain, deterministic Python — no LLM involved. Each check is a pure function taking a diff and returning pass/fail + reason:
   - `check_scope(diff, allowed_files)`
   - `check_size(diff, max_lines)`
   - `check_relevance(diff, package_name)`
   - `check_lockfile_consistency(diff)`
3. On any guardrail failure: discard the patch, retry remediation once or twice with the failure reason fed back to the model, then mark the finding as `needs_human` if still failing.
4. Wire `POST /findings/{id}/remediate`: takes the stored investigation, runs remediation, runs all guardrails, stores the diff (or the rejection reason).

**Definition of Done:** on `demo-app`, this produces exactly the 2-line lodash version bump; when you deliberately prompt for a broad "refactor the file" change, `guardrails.py` rejects it (write a test that asserts this explicitly — don't just eyeball it).

**GitHub mapping:** Milestone "v0.1 — Phase 3: Remediation". Issues: `Remediation engine`, `Scope guardrail`, `Size guardrail`, `Relevance guardrail`, `Lockfile guardrail`, `Retry/needs_human path`.

---

## Phase 4 — Validation Sandbox + GitHub PR

**What you add:**
```
app/validation/sandbox.py     ← Docker SDK: spin up a container, apply the patch, run tests, tear down
app/validation/sca.py         ← OSV.dev API client: rescan for the specific CVE post-patch
app/github/__init__.py
app/github/branches.py        ← create a branch from the diff
app/github/commits.py         ← commit the patched files
app/github/pull_requests.py   ← open the PR with the evidence report (PyGithub)
app/main.py                   ← + POST /findings/{id}/resolve  (runs the whole pipeline end to end)
requirements.txt              ← + docker, PyGithub, requests
.env.example                  ← + GITHUB_TOKEN
```

**How:**
1. `sandbox.py`: use the `docker` Python SDK to run a fresh container from a clean clone of the target repo, apply the diff, run `npm ci && npm test` (or the project's actual test command), capture pass/fail — the sandbox never touches your host filesystem or real credentials.
2. `sca.py`: call OSV.dev's API with the patched `package`/`version`, confirm the original CVE no longer matches.
3. If both pass, `branches.py` → `commits.py` → `pull_requests.py` create the branch, commit, and open the PR via `PyGithub`, using an evidence-report template (root cause, fix, validation checklist, files changed).
4. If either fails, do **not** open a PR — log the failure and mark the finding `rejected` or loop back to Phase 3 for a retry.
5. `POST /findings/{id}/resolve` chains Phases 2→3→4 as one call — this is your actual demo command.

**Definition of Done:** running the full pipeline against `demo-app` reliably (more than once) produces a real, mergeable GitHub PR containing the evidence report from the original plan. This is the v0.1 finish line.

**GitHub mapping:** Milestone "v0.1 — Phase 4: Validation & PR". Issues: `Docker sandbox runner`, `OSV rescan client`, `Branch/commit/PR creation`, `Evidence report template`, `End-to-end /resolve endpoint`, `Repeat-run reliability test`.

---

## After v0.1: same rules, new finding types

Every later phase follows the *exact same four-part pattern* above — only the finding `type` and the tool belt change. Nothing about the pipeline shape changes.

| Phase | What's added (high level) | How it differs from v0.1 |
|---|---|---|
| **v0.2 — SAST / secrets** | `app/validation/sast.py` (Semgrep wrapper), secret-pattern rules via `detect-secrets` | Same 4-phase flow; `affected_files` now come from a static analysis rule match instead of a dependency diff. Secrets are redacted in every report, never displayed or reused. |
| **v0.3 — Infrastructure (Terraform)** | `app/agents/tools.py` gains `get_terraform_resources()`; validation gains `terraform validate` + Checkov/Trivy IaC scan | Fix target is a `.tf` resource block instead of a `package.json` line; validation step swaps unit tests for `terraform plan`/`validate`. |
| **v0.4 — Cloud (AWS/Azure/GCP)** | Cloud SDK clients (`boto3`, etc.) as read-only investigation tools | Investigation reads live cloud config (read-only creds only); remediation still only ever proposes IaC/PR changes, never calls a cloud mutation API directly. |
| **v0.5 — Security Graph** | `app/graph/` module, Neo4j client | Aggregates findings across the above into a queryable graph for attack-path analysis — this is analysis on top of the existing pipeline, not a new remediation flow. |

Don't start any of these until Phase 4 of v0.1 is passing its Definition of Done repeatably.

---

## Quick reference: milestone → GitHub setup

1. Create one **GitHub Milestone** per phase (`v0.1 — Phase 1`, `v0.1 — Phase 2`, …)
2. Create one **Issue** per numbered step in that phase's "How" section above, assign it to the milestone
3. Label each issue with `phase:N` and the relevant cell (`cell:api`, `cell:agent`, `cell:validation`, `cell:git`)
4. A milestone is only closed when its **Definition of Done** command/test has actually been run and passed — not when all issues are checked
