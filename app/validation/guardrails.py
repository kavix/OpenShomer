import re
from typing import List, Tuple


class PatchGuardrails:
    """Deterministic validation guardrails applied to generated diffs."""

    @staticmethod
    def check_scope(diff: str, allowed_files: List[str]) -> Tuple[bool, str]:
        """Ensures the diff touches only allowed affected files."""
        touched_files = re.findall(r"^\+\+\+ b/(.+)$", diff, re.MULTILINE)
        for f in touched_files:
            if not any(f.endswith(allowed) or allowed.endswith(f) for allowed in allowed_files):
                return False, f"Guardrail Violation: Modified unauthorized file '{f}' outside affected scope."
        return True, "Scope check passed."

    @staticmethod
    def check_size(diff: str, max_lines: int = 300) -> Tuple[bool, str]:
        """Ensures the diff is minimal and does not exceed maximum blast radius."""
        added_or_removed = [line for line in diff.splitlines() if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))]
        if len(added_or_removed) > max_lines:
            return False, f"Guardrail Violation: Patch size ({len(added_or_removed)} lines) exceeds maximum limit ({max_lines} lines)."
        return True, "Size check passed."

    @staticmethod
    def check_permission_reduction(diff: str) -> Tuple[bool, str]:
        """Verifies that high-risk permissions were reduced and not expanded."""
        if "+  - \"shell:unrestricted\"" in diff or "+  - \"fs:write_all\"" in diff:
            return False, "Guardrail Violation: Attempted to add unrestricted shell or filesystem permissions."
        return True, "Permission reduction check passed."

    def validate_patch(self, diff: str, allowed_files: List[str], max_lines: int = 300) -> Tuple[bool, str]:
        if not diff.strip():
            return True, "Empty diff passed."
        
        ok_scope, reason = self.check_scope(diff, allowed_files)
        if not ok_scope:
            return False, reason

        ok_size, reason = self.check_size(diff, max_lines)
        if not ok_size:
            return False, reason

        ok_perms, reason = self.check_permission_reduction(diff)
        if not ok_perms:
            return False, reason

        return True, "All guardrails passed successfully."
