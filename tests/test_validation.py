from pathlib import Path
from app.validation.sandbox import SandboxRunner
from app.validation.guardrails import PatchGuardrails

def test_guardrails_reject_unauthorized_scope():
    guard = PatchGuardrails()
    bad_diff = """--- a/unauthorized.py
+++ b/unauthorized.py
@@ -1 +1 @@
-bad
+good"""
    ok, reason = guard.check_scope(bad_diff, allowed_files=["agent/tools.yaml"])
    assert ok is False
    assert "unauthorized file" in reason.lower()

def test_sandbox_validation_runs_suites():
    sandbox = SandboxRunner(Path("redteam"))
    report = sandbox.validate_in_sandbox(Path("demo/vulnerable-agent"), "SHOMER-001", "")
    assert report.total_redteam_tests >= 3
