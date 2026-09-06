from pathlib import Path

from app.frameworks import scan_all_agent_frameworks
from app.frameworks.crewai import CrewAIScanner
from app.frameworks.langchain import LangChainScanner
from app.frameworks.llamaindex import LlamaIndexScanner
from app.frameworks.skills import SkillFileScanner
from app.models.findings import FindingType


def test_skill_file_scanner(tmp_path: Path):
    skill_dir = tmp_path / "skills" / "deploy"
    skill_dir.mkdir(parents=True)
    skill_file = skill_dir / "SKILL.md"
    skill_file.write_text("""
# Deployment Skill
Run command with:
bash: unrestricted
""", encoding="utf-8")

    findings = SkillFileScanner.scan_skills(tmp_path)
    assert len(findings) == 1
    assert "SKILL" in findings[0].id
    assert "unrestricted" in findings[0].issue


def test_langchain_scanner(tmp_path: Path):
    agent_file = tmp_path / "langchain_agent.py"
    agent_file.write_text("""
from langchain.agents import Tool, AgentExecutor
import os

tool = Tool(
    name="system_exec",
    func=lambda cmd: os.system(cmd),
    description="Run shell commands",
    return_direct=True
)

agent = AgentExecutor(agent=None, tools=[tool])
""", encoding="utf-8")

    findings = LangChainScanner.scan_langchain_agents(tmp_path)
    assert len(findings) >= 1
    assert any("LangChain" in f.issue for f in findings)


def test_llamaindex_scanner(tmp_path: Path):
    agent_file = tmp_path / "llama_agent.py"
    agent_file.write_text("""
from llama_index.core.tools import FunctionTool
from llama_index.core.agent import ReActAgent
import os

tool = FunctionTool.from_defaults(fn=os.system)
agent = ReActAgent.from_tools([tool])
""", encoding="utf-8")

    findings = LlamaIndexScanner.scan_llamaindex_agents(tmp_path)
    assert len(findings) >= 1
    assert any("LlamaIndex" in f.issue for f in findings)


def test_crewai_scanner(tmp_path: Path):
    crew_file = tmp_path / "crew_agent.py"
    crew_file.write_text("""
from crewai import Agent

agent = Agent(
    role="DevOps Specialist",
    goal="Manage servers",
    backstory="You have full control",
    allow_delegation=True,
    tools=["shell_tool"]
)
""", encoding="utf-8")

    findings = CrewAIScanner.scan_crewai_agents(tmp_path)
    assert len(findings) == 1
    assert "CrewAI" in findings[0].issue
    assert "allow_delegation" in findings[0].issue


def test_scan_all_agent_frameworks_combined(tmp_path: Path):
    # Create a skill file
    skill_file = tmp_path / "SKILL.md"
    skill_file.write_text("bash: unrestricted", encoding="utf-8")

    # Create a langchain agent
    lc_file = tmp_path / "agent.py"
    lc_file.write_text("tool = Tool(name='t', return_direct=True, func=os.system)", encoding="utf-8")

    findings = scan_all_agent_frameworks(tmp_path)
    assert len(findings) == 2


def test_langchain_vectorstore_retriever_missing_filter(tmp_path: Path):
    agent_file = tmp_path / "rag_chain.py"
    agent_file.write_text(
        """
from langchain_core.vectorstores import VectorStoreRetriever

retriever = VectorStoreRetriever(vectorstore=store)
chunks = retriever.vectorstore.similarity_search(query)
""",
        encoding="utf-8",
    )

    findings = LangChainScanner.scan_langchain_agents(tmp_path)
    assert any(f.metadata.get("rule_id") == "MISSING_VECTOR_METADATA_FILTER" for f in findings)
    assert any(f.type == FindingType.VECTOR_AND_EMBEDDING_WEAKNESS for f in findings)
    assert any("MISSING_VECTOR_METADATA_FILTER" in f.issue for f in findings)


def test_langchain_vectorstore_retriever_unbounded_top_k(tmp_path: Path):
    agent_file = tmp_path / "rag_chain.py"
    agent_file.write_text(
        """
from langchain_core.vectorstores import VectorStoreRetriever

retriever = VectorStoreRetriever(
    vectorstore=store,
    search_kwargs={"filter": {"tenant_id": tenant_id}, "k": 200},
)
""",
        encoding="utf-8",
    )

    findings = LangChainScanner.scan_langchain_agents(tmp_path)
    assert any(f.metadata.get("rule_id") == "UNBOUNDED_VECTOR_TOP_K" for f in findings)
    assert not any(f.metadata.get("rule_id") == "MISSING_VECTOR_METADATA_FILTER" for f in findings)


def test_langchain_flags_unfiltered_search_beside_filtered_retriever(tmp_path: Path):
    agent_file = tmp_path / "rag_chain.py"
    agent_file.write_text(
        """
from langchain_core.vectorstores import VectorStoreRetriever

retriever = VectorStoreRetriever(
    vectorstore=store,
    search_kwargs={"filter": {"tenant_id": tenant_id}, "k": 4},
)
chunks = store.similarity_search(query)
""",
        encoding="utf-8",
    )

    findings = LangChainScanner.scan_langchain_agents(tmp_path)
    assert any(f.metadata.get("rule_id") == "MISSING_VECTOR_METADATA_FILTER" for f in findings)


def test_llamaindex_vectorstore_index_missing_filter(tmp_path: Path):
    agent_file = tmp_path / "llama_rag.py"
    agent_file.write_text(
        """
from llama_index.core import VectorStoreIndex

index = VectorStoreIndex.from_documents(docs)
engine = index.as_query_engine(similarity_top_k=8)
""",
        encoding="utf-8",
    )

    findings = LlamaIndexScanner.scan_llamaindex_agents(tmp_path)
    assert any(f.metadata.get("rule_id") == "MISSING_VECTOR_METADATA_FILTER" for f in findings)
    assert any(f.type == FindingType.VECTOR_AND_EMBEDDING_WEAKNESS for f in findings)
