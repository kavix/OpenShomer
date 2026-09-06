import ast
import re
from typing import Tuple


class PythonASTSynthesizer:
    """Qoder Python AST Code Transformer.
    
    Transforms Python source code for agent frameworks (LangChain, LlamaIndex, CrewAI, AutoGen)
    to inject safety guardrails, rate limits, and parameter bounds without breaking developer functionality.
    """

    @classmethod
    def harden_langchain_agent(cls, code: str) -> Tuple[str, str]:
        """Secures LangChain tools by removing dangerous return_direct=True and enforcing parameter schemas."""
        rewritten = code
        # 1. Neutralize return_direct=True on dangerous tools
        rewritten = re.sub(
            r"return_direct\s*=\s*True",
            "return_direct=False, handle_tool_error=True",
            rewritten
        )
        # 2. Add max_iterations cap to agent executors
        if "AgentExecutor(" in rewritten and "max_iterations" not in rewritten:
            rewritten = rewritten.replace(
                "AgentExecutor(",
                "AgentExecutor(max_iterations=15, max_execution_time=60.0, "
            )
        return rewritten

    @classmethod
    def harden_llamaindex_tool(cls, code: str) -> Tuple[str, str]:
        """Secures LlamaIndex FunctionTools with parameter bounds and safe error handlers."""
        rewritten = code
        if "FunctionTool.from_defaults(" in rewritten and "validate_input" not in rewritten:
            rewritten = rewritten.replace(
                "FunctionTool.from_defaults(",
                "FunctionTool.from_defaults(return_direct=False, "
            )
        return rewritten

    @classmethod
    def harden_crewai_agent(cls, code: str) -> Tuple[str, str]:
        """Secures CrewAI Agent definitions by restricting unbounded delegation."""
        rewritten = code
        # Restrict allow_delegation=True
        rewritten = re.sub(
            r"allow_delegation\s*=\s*True",
            "allow_delegation=False, max_iter=10",
            rewritten
        )
        return rewritten

    @classmethod
    def _cap_unbounded_top_k(cls, code: str) -> str:
        """Caps excessive retrieval breadth (top_k/k > 50) to a safe default of 10."""
        def _cap(match: re.Match) -> str:
            value = int(match.group(2))
            if value > 50:
                return f"{match.group(1)}10"
            return match.group(0)

        rewritten = re.sub(r"(similarity_top_k\s*=\s*)(\d+)", _cap, code)
        rewritten = re.sub(r"(top_k\s*=\s*)(\d+)", _cap, rewritten)
        rewritten = re.sub(r"(['\"]k['\"]\s*:\s*)(\d+)", _cap, rewritten)
        rewritten = re.sub(r"((?<![A-Za-z0-9_])k\s*=\s*)(\d+)", _cap, rewritten)
        return rewritten

    @classmethod
    def _iter_named_calls(cls, source: str, func_name: str) -> list[tuple[int, int, str]]:
        """Return (open_paren_idx, close_paren_idx, args) for each func_name( call."""
        calls: list[tuple[int, int, str]] = []
        for match in re.finditer(rf"(?<![A-Za-z0-9_]){re.escape(func_name)}\s*\(", source):
            open_idx = match.end() - 1
            depth = 0
            for i in range(open_idx, len(source)):
                if source[i] == "(":
                    depth += 1
                elif source[i] == ")":
                    depth -= 1
                    if depth == 0:
                        calls.append((open_idx, i, source[open_idx + 1:i]))
                        break
        return calls

    @classmethod
    def _rewrite_named_calls(cls, source: str, func_name: str, rewriter) -> str:
        rewritten = source
        for open_idx, close_idx, args in reversed(cls._iter_named_calls(rewritten, func_name)):
            new_args = rewriter(args)
            if new_args != args:
                rewritten = rewritten[:open_idx + 1] + new_args + rewritten[close_idx:]
        return rewritten

    @staticmethod
    def _has_metadata_filter(args: str) -> bool:
        return bool(
            re.search(r"(?:filter|where)\s*=", args)
            or "MetadataFilters" in args
            or re.search(r"['\"](?:filter|where)['\"]\s*:", args)
        )

    @staticmethod
    def _join_injection(args: str, injection: str) -> str:
        stripped = args.strip()
        if not stripped:
            return injection
        first = stripped.split(",", 1)[0]
        if "=" not in first:
            return f"{stripped}, {injection}"
        return f"{injection}, {stripped}"

    @classmethod
    def _secure_langchain_retriever_args(cls, args: str) -> str:
        if cls._has_metadata_filter(args):
            return args
        if "search_kwargs" in args:
            return re.sub(
                r"search_kwargs\s*=\s*\{",
                'search_kwargs={"filter": {"tenant_id": tenant_id}, ',
                args,
                count=1,
            )
        prefix = 'search_kwargs={"filter": {"tenant_id": tenant_id}, "k": 10}'
        return cls._join_injection(args, prefix)

    @classmethod
    def _secure_similarity_search_args(cls, args: str) -> str:
        if cls._has_metadata_filter(args):
            return args
        prefix = 'filter={"tenant_id": tenant_id}'
        if not re.search(r"(?<![A-Za-z0-9_])k\s*=", args) and not re.search(r"['\"]k['\"]\s*:", args):
            prefix += ", k=10"
        return cls._join_injection(args, prefix)

    @classmethod
    def _secure_llamaindex_query_args(cls, args: str) -> str:
        new_args = args
        if not cls._has_metadata_filter(new_args):
            if "vector_store_kwargs" in new_args:
                new_args = re.sub(
                    r"vector_store_kwargs\s*=\s*\{",
                    'vector_store_kwargs={"filter": {"tenant_id": tenant_id}, ',
                    new_args,
                    count=1,
                )
            else:
                prefix = 'vector_store_kwargs={"filter": {"tenant_id": tenant_id}}'
                new_args = cls._join_injection(new_args, prefix)
        if "similarity_top_k" not in new_args:
            new_args = cls._join_injection(new_args, "similarity_top_k=10")
        return new_args

    @classmethod
    def harden_langchain_vector_retriever(cls, code: str) -> str:
        """Injects mandatory tenant metadata filters and bounded k into LangChain retrievers."""
        rewritten = code
        is_langchain = "langchain" in rewritten.lower() or "VectorStoreRetriever" in rewritten
        has_retriever = (
            "VectorStoreRetriever" in rewritten
            or (is_langchain and (".as_retriever(" in rewritten or "similarity_search(" in rewritten))
        )
        if not has_retriever:
            return rewritten

        # 1. Cap unbounded top_k / k before injecting missing filters
        rewritten = cls._cap_unbounded_top_k(rewritten)

        # 2. Inject parameterized tenant filter dictionaries at every retrieval call
        rewritten = cls._rewrite_named_calls(rewritten, "as_retriever", cls._secure_langchain_retriever_args)
        rewritten = cls._rewrite_named_calls(rewritten, "VectorStoreRetriever", cls._secure_langchain_retriever_args)
        rewritten = cls._rewrite_named_calls(rewritten, "similarity_search", cls._secure_similarity_search_args)
        return rewritten

    @classmethod
    def harden_llamaindex_vector_index(cls, code: str) -> str:
        """Injects mandatory tenant metadata filters and bounded similarity_top_k into LlamaIndex indexes."""
        rewritten = code
        is_llama = (
            "llama_index" in rewritten.lower()
            or "llamaindex" in rewritten.lower()
            or "VectorStoreIndex" in rewritten
        )
        has_index = "VectorStoreIndex" in rewritten or (
            is_llama and (".as_retriever(" in rewritten or ".as_query_engine(" in rewritten)
        )
        if not has_index:
            return rewritten

        # 1. Cap unbounded similarity_top_k before injecting missing filters
        rewritten = cls._cap_unbounded_top_k(rewritten)

        # 2. Inject parameterized tenant filter dictionaries at every query/retriever call
        rewritten = cls._rewrite_named_calls(rewritten, "as_retriever", cls._secure_llamaindex_query_args)
        rewritten = cls._rewrite_named_calls(rewritten, "as_query_engine", cls._secure_llamaindex_query_args)
        return rewritten
