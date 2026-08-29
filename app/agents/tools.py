from pathlib import Path
from typing import List, Dict, Any, Optional
import os
import yaml
import json


class AgentRepoTools:
    """Strictly controlled, read-only tools for the investigation agent."""

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root.resolve()

    def _resolve_safe(self, rel_path: str) -> Path:
        target = (self.workspace_root / rel_path).resolve()
        if not str(target).startswith(str(self.workspace_root)):
            raise ValueError(f"Access denied: path '{rel_path}' escapes workspace.")
        return target

    def read_file(self, rel_path: str) -> str:
        """Reads file content from workspace."""
        path = self._resolve_safe(rel_path)
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"File '{rel_path}' does not exist.")
        return path.read_text(encoding="utf-8")

    def search_code(self, query: str, extension_filter: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Searches for pattern matches across files in workspace."""
        results = []
        for root, _, files in os.walk(self.workspace_root):
            for file in files:
                if file.startswith("."):
                    continue
                ext = Path(file).suffix
                if extension_filter and ext not in extension_filter:
                    continue
                file_path = Path(root) / file
                rel_path = str(file_path.relative_to(self.workspace_root))
                try:
                    content = file_path.read_text(encoding="utf-8")
                    for idx, line in enumerate(content.splitlines(), start=1):
                        if query.lower() in line.lower():
                            results.append({
                                "file": rel_path,
                                "line": idx,
                                "snippet": line.strip()
                            })
                except Exception:
                    continue
        return results

    def list_files(self, sub_dir: str = "") -> List[str]:
        """Lists files relative to workspace."""
        target_dir = self._resolve_safe(sub_dir)
        files_list = []
        for root, _, files in os.walk(target_dir):
            for file in files:
                if not file.startswith("."):
                    rel = str((Path(root) / file).relative_to(self.workspace_root))
                    files_list.append(rel)
        return files_list

    def list_tools(self, tools_config_path: str = "agent/tools.yaml") -> List[Dict[str, Any]]:
        """Parses tool definitions from YAML."""
        try:
            content = self.read_file(tools_config_path)
            data = yaml.safe_load(content)
            return data.get("tools", [])
        except Exception as e:
            return [{"error": f"Failed to parse tools config: {str(e)}"}]

    def get_prompt_context(self, prompt_path: str = "prompts/system.md") -> Dict[str, Any]:
        """Reads system prompt and provides metadata."""
        content = self.read_file(prompt_path)
        return {
            "path": prompt_path,
            "length_chars": len(content),
            "content": content
        }
