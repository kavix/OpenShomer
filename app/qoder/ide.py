import difflib
from pathlib import Path
from typing import Any

from app.qoder.diff_synthesizer import DiffSynthesizer
from app.qoder.prompt_fencing import PromptFenceBuilder
from app.qoder.python_ast import PythonASTSynthesizer


class QoderIDE:
    """Qoder: AI-Native Agentic Development Backbone.
    
    Translates vulnerability findings into minimal, scoped, least-privilege
    code diffs and defensive prompt fences across YAML, JSON, Markdown, and Python Agent Frameworks.
    """

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root
        self.diff_synthesizer = DiffSynthesizer()
        self.prompt_fencing = PromptFenceBuilder()
        self.python_synthesizer = PythonASTSynthesizer()

    def generate_remediation_diff(self, relative_path: str) -> dict[str, Any]:
        """Generate precise least-privilege diff and rewritten content for a target file."""
        target = self.workspace_root / relative_path
        if not target.exists() or not target.is_file():
            return {"file": relative_path, "diff": "", "content": "", "success": False, "error": "File not found"}

        content = target.read_text(encoding="utf-8")
        diff = ""
        rewritten = content

        if relative_path.endswith(("tools.yaml", "tools.yml")):
            rewritten, diff = self.diff_synthesizer.synthesize_tool_yaml(content)
        elif relative_path.endswith(".json") and "mcp" in relative_path:
            rewritten, diff = self.diff_synthesizer.synthesize_mcp_json(content)
        elif relative_path.endswith((".md", ".prompt")) or "prompt" in relative_path:
            rewritten, diff = self.diff_synthesizer.synthesize_prompt_fence(content, filename=relative_path)
        elif relative_path.endswith(".py"):
            # Python Frameworks (LangChain, LlamaIndex, CrewAI)
            if "langchain" in content.lower():
                rewritten = self.python_synthesizer.harden_langchain_agent(content)
            elif "llamaindex" in content.lower() or "functiontool" in content.lower():
                rewritten = self.python_synthesizer.harden_llamaindex_tool(content)
            elif "crewai" in content.lower():
                rewritten = self.python_synthesizer.harden_crewai_agent(content)
            
            if rewritten != content:
                diff_lines = list(difflib.unified_diff(
                    content.splitlines(keepends=True),
                    rewritten.splitlines(keepends=True),
                    fromfile=f"a/{relative_path}",
                    tofile=f"b/{relative_path}",
                ))
                diff = "".join(diff_lines)

        return {
            "file": relative_path,
            "original_content": content,
            "rewritten_content": rewritten,
            "diff": diff,
            "success": bool(diff),
        }
