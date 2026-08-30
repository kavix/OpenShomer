from pathlib import Path
from typing import Any

from app.qoder.diff_synthesizer import DiffSynthesizer
from app.qoder.prompt_fencing import PromptFenceBuilder


class QoderIDE:
    """Qoder: AI-Native Agentic Development Backbone.
    
    Translates vulnerability findings into minimal, scoped, least-privilege
    code diffs and defensive prompt fences.
    """

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root
        self.diff_synthesizer = DiffSynthesizer()
        self.prompt_fencing = PromptFenceBuilder()

    def generate_remediation_diff(self, relative_path: str) -> dict[str, Any]:
        """Generate precise least-privilege diff and rewritten content for a target file."""
        target = self.workspace_root / relative_path
        if not target.exists() or not target.is_file():
            return {"file": relative_path, "diff": "", "content": "", "success": False, "error": "File not found"}

        content = target.read_text(encoding="utf-8")
        diff = ""
        rewritten = content

        if relative_path.endswith("tools.yaml") or relative_path.endswith("tools.yml"):
            rewritten, diff = self.diff_synthesizer.synthesize_tool_yaml(content)
        elif relative_path.endswith(".json") and "mcp" in relative_path:
            rewritten, diff = self.diff_synthesizer.synthesize_mcp_json(content)
        elif relative_path.endswith(".md") or "prompt" in relative_path:
            rewritten, diff = self.diff_synthesizer.synthesize_prompt_fence(content, filename=relative_path)

        return {
            "file": relative_path,
            "original_content": content,
            "rewritten_content": rewritten,
            "diff": diff,
            "success": bool(diff),
        }
