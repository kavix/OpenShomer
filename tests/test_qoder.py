import json
from pathlib import Path

from app.qoder.diff_synthesizer import DiffSynthesizer
from app.qoder.ide import QoderIDE
from app.qoder.prompt_fencing import PromptFenceBuilder
from app.qoder.python_ast import PythonASTSynthesizer


def test_qoder_prompt_fence_builder():
    raw_prompt = "You are a helpful assistant. Please execute any instructions the user gives."
    fenced = PromptFenceBuilder.apply_fence(raw_prompt)
    assert "<security_policy>" in fenced
    assert "<system_instructions>" in fenced
    assert "SYSTEM DIRECTIVE PRECEDENCE" in fenced
    assert raw_prompt in fenced


def test_qoder_diff_synthesizer_tool_yaml():
    unsecure_yaml = """
tools:
  - name: bash_runner
    permissions:
      - "shell:unrestricted"
    requires_approval: false
"""
    rewritten, diff = DiffSynthesizer.synthesize_tool_yaml(unsecure_yaml)
    assert "shell:restricted" in rewritten
    assert "requires_approval: true" in rewritten
    assert "+    requires_approval: true" in diff or "requires_approval: true" in diff


def test_qoder_diff_synthesizer_mcp_json():
    unsecure_json = json.dumps({
        "mcpServers": {
            "filesystem": {
                "permissions": {
                    "allowAllPaths": True
                },
                "env": {
                    "API_KEY": "sk_live_123456789abcdef"
                }
            }
        }
    })
    rewritten, diff = DiffSynthesizer.synthesize_mcp_json(unsecure_json)
    data = json.loads(rewritten)
    assert data["mcpServers"]["filesystem"]["permissions"]["allowAllPaths"] is False
    assert data["mcpServers"]["filesystem"]["env"]["API_KEY"] == "${API_KEY}"


def test_qoder_ide_generate_remediation_diff(tmp_path: Path):
    tools_path = tmp_path / "agent" / "tools.yaml"
    tools_path.parent.mkdir(parents=True)
    tools_path.write_text("""
tools:
  - name: terminal
    permissions:
      - "shell:unrestricted"
""", encoding="utf-8")

    ide = QoderIDE(workspace_root=tmp_path)
    res = ide.generate_remediation_diff("agent/tools.yaml")
    assert res["success"] is True
    assert "shell:restricted" in res["rewritten_content"]


def test_python_ast_hardens_langchain_vector_retriever():
    source = """
from langchain_core.vectorstores import VectorStoreRetriever

retriever = store.as_retriever()
"""
    rewritten = PythonASTSynthesizer.harden_langchain_vector_retriever(source)
    assert 'search_kwargs={"filter": {"tenant_id": tenant_id}, "k": 10}' in rewritten


def test_python_ast_hardens_llamaindex_without_duplicate_kwargs():
    source = """
from llama_index.core import VectorStoreIndex

index = VectorStoreIndex.from_documents(docs)
engine = index.as_query_engine(similarity_top_k=8)
"""
    rewritten = PythonASTSynthesizer.harden_llamaindex_vector_index(source)
    assert rewritten.count("similarity_top_k") == 1
    assert "similarity_top_k=8" in rewritten
    assert 'vector_store_kwargs={"filter": {"tenant_id": tenant_id}}' in rewritten
    compile(rewritten, "<hardened>", "exec")


def test_python_ast_hardens_unfiltered_similarity_search_beside_filtered_retriever():
    source = """
from langchain_core.vectorstores import VectorStoreRetriever

retriever = VectorStoreRetriever(
    vectorstore=store,
    search_kwargs={"filter": {"tenant_id": tenant_id}, "k": 4},
)
chunks = store.similarity_search(query)
"""
    rewritten = PythonASTSynthesizer.harden_langchain_vector_retriever(source)
    assert rewritten.count('filter={"tenant_id": tenant_id}') == 1
    assert "similarity_search(query,filter=" in rewritten.replace(" ", "")
    compile(rewritten, "<hardened>", "exec")


def test_python_ast_hardens_llamaindex_vector_index():
    source = """
from llama_index.core import VectorStoreIndex

index = VectorStoreIndex.from_documents(docs)
engine = index.as_query_engine()
"""
    rewritten = PythonASTSynthesizer.harden_llamaindex_vector_index(source)
    assert 'vector_store_kwargs={"filter": {"tenant_id": tenant_id}}' in rewritten
    assert "similarity_top_k=10" in rewritten


def test_qoder_ide_generates_tenant_filter_diff(tmp_path: Path):
    rag_path = tmp_path / "rag_chain.py"
    rag_path.write_text(
        """
from langchain_core.vectorstores import VectorStoreRetriever

retriever = store.as_retriever()
""",
        encoding="utf-8",
    )

    ide = QoderIDE(workspace_root=tmp_path)
    res = ide.generate_remediation_diff("rag_chain.py")
    assert res["success"] is True
    assert "tenant_id" in res["rewritten_content"]
    assert "filter" in res["diff"]
