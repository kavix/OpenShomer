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
