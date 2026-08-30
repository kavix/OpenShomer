from pathlib import Path
from typing import List
from app.models.findings import Finding
from app.frameworks.skills import SkillFileScanner
from app.frameworks.langchain import LangChainScanner
from app.frameworks.llamaindex import LlamaIndexScanner
from app.frameworks.crewai import CrewAIScanner


def scan_all_agent_frameworks(workspace_root: Path) -> List[Finding]:
    """v0.2 Richer Agent Graphs: Scan skill files, LangChain, LlamaIndex, and CrewAI frameworks."""
    findings: List[Finding] = []
    findings.extend(SkillFileScanner.scan_skills(workspace_root))
    findings.extend(LangChainScanner.scan_langchain_agents(workspace_root))
    findings.extend(LlamaIndexScanner.scan_llamaindex_agents(workspace_root))
    findings.extend(CrewAIScanner.scan_crewai_agents(workspace_root))
    return findings


__all__ = [
    "SkillFileScanner",
    "LangChainScanner",
    "LlamaIndexScanner",
    "CrewAIScanner",
    "scan_all_agent_frameworks",
]
