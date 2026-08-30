from pathlib import Path
from typing import List

from app.frameworks.crewai import CrewAIScanner
from app.frameworks.langchain import LangChainScanner
from app.frameworks.llamaindex import LlamaIndexScanner
from app.frameworks.skills import SkillFileScanner
from app.models.findings import Finding


def scan_all_agent_frameworks(workspace_root: Path) -> list[Finding]:
    """v0.2 Richer Agent Graphs: Scan skill files, LangChain, LlamaIndex, and CrewAI frameworks."""
    findings: list[Finding] = []
    findings.extend(SkillFileScanner.scan_skills(workspace_root))
    findings.extend(LangChainScanner.scan_langchain_agents(workspace_root))
    findings.extend(LlamaIndexScanner.scan_llamaindex_agents(workspace_root))
    findings.extend(CrewAIScanner.scan_crewai_agents(workspace_root))
    return findings


__all__ = [
    "CrewAIScanner",
    "LangChainScanner",
    "LlamaIndexScanner",
    "SkillFileScanner",
    "scan_all_agent_frameworks",
]
