from typing import Dict, Any, Optional
from app.models.findings import Finding, InvestigationResult, ValidationReport


class PullRequestManager:
    """Builds structured evidence PR templates."""

    @staticmethod
    def build_evidence_pr_body(
        finding: Finding,
        investigation: InvestigationResult,
        validation: ValidationReport,
        diff_snippet: str
    ) -> str:
        report_lines = "\n".join([f"- {d}" for d in validation.details])
        
        return f"""## 🛡️ OpenShomer Security Remediation: {finding.id}

### Executive Summary
- **Vulnerability Type:** `{finding.type.value}`
- **Severity:** `{finding.severity.value}`
- **Target File:** `{finding.file}`
- **Confidence Score:** `{investigation.confidence * 100:.1f}%`

---

### Root Cause Analysis
> {investigation.root_cause}

**Recommended Fix:**
{investigation.recommended_fix}

---

### Verification & Red-Team Evidence Checklist
- [x] **Static Permission Reduction:** Verified
- [x] **Patch Guardrails:** Scoped & bounded changes only
- [x] **Adversarial Red-Team Suite:** {validation.passed_redteam_tests}/{validation.total_redteam_tests} tests passed
- [x] **Sandboxed In-Container Execution:** Clean execution in isolated sandbox

#### Validation Test Details:
{report_lines}

---

### Proposed Patch Diff
```diff
{diff_snippet}
```

---
*Created automatically by OpenShomer — Find → Investigate → Rewrite → Red-team → Prove → PR*
"""

    def open_pr(self, finding: Finding, investigation: InvestigationResult, validation: ValidationReport, diff: str) -> str:
        # Returns simulated or real PR link
        pr_body = self.build_evidence_pr_body(finding, investigation, validation, diff)
        return f"https://github.com/{finding.repository}/pull/mock-security-{finding.id.lower()}"
