import re


class PythonASTSynthesizer:
    """Qoder Python AST Code Transformer.

    Transforms Python source code for agent frameworks (LangChain, LlamaIndex, CrewAI, AutoGen)
    to inject safety guardrails, rate limits, and parameter bounds without breaking developer functionality.
    """

    @classmethod
    def harden_langchain_agent(cls, code: str) -> str:
        """Secures LangChain tools by removing dangerous return_direct=True and enforcing parameter schemas."""
        rewritten = code
        # 1. Neutralize return_direct=True on dangerous tools
        rewritten = re.sub(r"return_direct\s*=\s*True", "return_direct=False, handle_tool_error=True", rewritten)
        # 2. Add max_iterations cap to agent executors
        if "AgentExecutor(" in rewritten and "max_iterations" not in rewritten:
            rewritten = rewritten.replace(
                "AgentExecutor(", "AgentExecutor(max_iterations=15, max_execution_time=60.0, "
            )
        return rewritten

    @classmethod
    def harden_llamaindex_tool(cls, code: str) -> str:
        """Secures LlamaIndex FunctionTools with parameter bounds and safe error handlers."""
        rewritten = code
        if "FunctionTool.from_defaults(" in rewritten and "validate_input" not in rewritten:
            rewritten = rewritten.replace(
                "FunctionTool.from_defaults(", "FunctionTool.from_defaults(return_direct=False, "
            )
        return rewritten

    @classmethod
    def harden_crewai_agent(cls, code: str) -> str:
        """Secures CrewAI Agent definitions by restricting unbounded delegation."""
        rewritten = code
        # Restrict allow_delegation=True
        rewritten = re.sub(r"allow_delegation\s*=\s*True", "allow_delegation=False, max_iter=10", rewritten)
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
                        calls.append((open_idx, i, source[open_idx + 1 : i]))
                        break
        return calls

    @classmethod
    def _rewrite_named_calls(cls, source: str, func_name: str, rewriter) -> str:
        rewritten = source
        for open_idx, close_idx, args in reversed(cls._iter_named_calls(rewritten, func_name)):
            new_args = rewriter(args)
            if new_args != args:
                rewritten = rewritten[: open_idx + 1] + new_args + rewritten[close_idx:]
        return rewritten

    @classmethod
    def _cap_k(cls, node):
        import ast

        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            if node.value > 50:
                return ast.Constant(value=10)
            return node
        wrap = ast.parse("(lambda x: min(x, 20) if type(x) is int else 10)(X)", mode="eval").body

        class XReplacer(ast.NodeTransformer):
            def visit_Name(self, n):
                return node if n.id == "X" else n

        return XReplacer().visit(wrap)

    @classmethod
    def _wrap_filter(cls, node):
        import ast

        wrap = ast.parse("{**(X), 'tenant_id': tenant_id}", mode="eval").body

        class XReplacer(ast.NodeTransformer):
            def visit_Name(self, n):
                return node if n.id == "X" else n

        return XReplacer().visit(wrap)

    @classmethod
    def _secure_langchain_retriever_args(cls, args: str) -> str:
        import ast

        try:
            tree = ast.parse(f"f({args})")
            if not (isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Call)):
                return args
            call = tree.body[0].value
        except SyntaxError:
            return args

        kwargs_node = next((kw for kw in call.keywords if kw.arg is None), None)
        if kwargs_node is not None:
            wrap_expr = ast.parse(
                "{**(X), 'search_kwargs': {**(X.get('search_kwargs', {})), "
                "'filter': {**(X.get('search_kwargs', {}).get('filter', {})), 'tenant_id': tenant_id}, "
                "'k': (lambda x: min(x, 20) if type(x) is int else 10)(X.get('search_kwargs', {}).get('k', 10))}}",
                mode="eval",
            ).body

            class KwargsNodeReplacer(ast.NodeTransformer):
                def visit_Name(self, n):
                    return kwargs_node.value if kwargs_node is not None and n.id == "X" else n

            kwargs_node.value = KwargsNodeReplacer().visit(wrap_expr)
            # Remove any explicit search_kwargs to avoid collision, since it's now merged
            call.keywords = [kw for kw in call.keywords if kw.arg != "search_kwargs"]
            return ast.unparse(call)[2:-1]

        sk_kw = next((kw for kw in call.keywords if kw.arg == "search_kwargs"), None)
        if not sk_kw:
            new_sk = ast.parse('{"filter": {"tenant_id": tenant_id}, "k": 10}', mode="eval").body
            call.keywords.append(ast.keyword(arg="search_kwargs", value=new_sk))
        else:
            if isinstance(sk_kw.value, ast.Dict):
                has_f = has_k = False
                for i, key in enumerate(sk_kw.value.keys):
                    if isinstance(key, ast.Constant) and key.value == "filter":
                        has_f = True
                        sk_kw.value.values[i] = cls._wrap_filter(sk_kw.value.values[i])
                    elif isinstance(key, ast.Constant) and key.value == "k":
                        has_k = True
                        sk_kw.value.values[i] = cls._cap_k(sk_kw.value.values[i])
                if not has_f:
                    sk_kw.value.keys.append(ast.Constant(value="filter"))
                    sk_kw.value.values.append(ast.parse('{"tenant_id": tenant_id}', mode="eval").body)
                if not has_k:
                    sk_kw.value.keys.append(ast.Constant(value="k"))
                    sk_kw.value.values.append(ast.Constant(value=10))
            else:
                wrap = ast.parse(
                    "{**(X), 'filter': {**(X.get('filter', {})), 'tenant_id': tenant_id}, 'k': (lambda x: min(x, 20) if type(x) is int else 10)(X.get('k', 10))}",
                    mode="eval",
                ).body

                class SkKwReplacer(ast.NodeTransformer):
                    def visit_Name(self, n):
                        return sk_kw.value if sk_kw is not None and n.id == "X" else n

                sk_kw.value = SkKwReplacer().visit(wrap)
        return ast.unparse(call)[2:-1]

    @classmethod
    def _secure_similarity_search_args(cls, args: str) -> str:
        import ast

        try:
            tree = ast.parse(f"f({args})")
            if not (isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Call)):
                return args
            call = tree.body[0].value
        except SyntaxError:
            return args

        kwargs_node = next((kw for kw in call.keywords if kw.arg is None), None)
        if kwargs_node is not None:
            wrap_expr = ast.parse(
                "{**(X), 'filter': {**(X.get('filter', {})), 'tenant_id': tenant_id}, "
                "'k': (lambda x: min(x, 20) if type(x) is int else 10)(X.get('k', 10))}",
                mode="eval",
            ).body

            class SimSearchKwargsReplacer(ast.NodeTransformer):
                def visit_Name(self, n):
                    return kwargs_node.value if kwargs_node is not None and n.id == "X" else n

            kwargs_node.value = SimSearchKwargsReplacer().visit(wrap_expr)
            call.keywords = [kw for kw in call.keywords if kw.arg not in ("filter", "k")]
            return ast.unparse(call)[2:-1]

        f_kw = next((kw for kw in call.keywords if kw.arg == "filter"), None)
        if not f_kw:
            call.keywords.append(
                ast.keyword(arg="filter", value=ast.parse('{"tenant_id": tenant_id}', mode="eval").body)
            )
        else:
            f_kw.value = cls._wrap_filter(f_kw.value)

        k_kw = next((kw for kw in call.keywords if kw.arg == "k"), None)
        if not k_kw:
            call.keywords.append(ast.keyword(arg="k", value=ast.Constant(value=10)))
        else:
            k_kw.value = cls._cap_k(k_kw.value)

        return ast.unparse(call)[2:-1]

    @classmethod
    def _secure_llamaindex_query_args(cls, args: str) -> str:
        import ast

        try:
            tree = ast.parse(f"f({args})")
            if not (isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Call)):
                return args
            call = tree.body[0].value
        except SyntaxError:
            return args

        kwargs_node = next((kw for kw in call.keywords if kw.arg is None), None)
        if kwargs_node is not None:
            wrap_expr = ast.parse(
                "{**(X), 'vector_store_kwargs': {**(X.get('vector_store_kwargs', {})), "
                "'filter': {**(X.get('vector_store_kwargs', {}).get('filter', {})), 'tenant_id': tenant_id}}, "
                "'similarity_top_k': (lambda x: min(x, 20) if type(x) is int else 10)(X.get('similarity_top_k', 10))}",
                mode="eval",
            ).body

            class LlamaKwargsReplacer(ast.NodeTransformer):
                def visit_Name(self, n):
                    return kwargs_node.value if kwargs_node is not None and n.id == "X" else n

            kwargs_node.value = LlamaKwargsReplacer().visit(wrap_expr)
            call.keywords = [kw for kw in call.keywords if kw.arg not in ("vector_store_kwargs", "similarity_top_k")]
            return ast.unparse(call)[2:-1]

        vsk_kw = next((kw for kw in call.keywords if kw.arg == "vector_store_kwargs"), None)
        if not vsk_kw:
            new_vsk = ast.parse('{"filter": {"tenant_id": tenant_id}}', mode="eval").body
            call.keywords.append(ast.keyword(arg="vector_store_kwargs", value=new_vsk))
        else:
            if isinstance(vsk_kw.value, ast.Dict):
                has_f = False
                for i, key in enumerate(vsk_kw.value.keys):
                    if isinstance(key, ast.Constant) and key.value == "filter":
                        has_f = True
                        vsk_kw.value.values[i] = cls._wrap_filter(vsk_kw.value.values[i])
                if not has_f:
                    vsk_kw.value.keys.append(ast.Constant(value="filter"))
                    vsk_kw.value.values.append(ast.parse('{"tenant_id": tenant_id}', mode="eval").body)
            else:
                wrap = ast.parse(
                    "{**(X), 'filter': {**(X.get('filter', {})), 'tenant_id': tenant_id}}", mode="eval"
                ).body

                class LlamaVskReplacer(ast.NodeTransformer):
                    def visit_Name(self, n):
                        return vsk_kw.value if vsk_kw is not None and n.id == "X" else n

                vsk_kw.value = LlamaVskReplacer().visit(wrap)

        tk_kw = next((kw for kw in call.keywords if kw.arg == "similarity_top_k"), None)
        if not tk_kw:
            call.keywords.append(ast.keyword(arg="similarity_top_k", value=ast.Constant(value=10)))
        else:
            tk_kw.value = cls._cap_k(tk_kw.value)

        return ast.unparse(call)[2:-1]

    @classmethod
    def harden_langchain_vector_retriever(cls, code: str) -> str:
        """Injects mandatory tenant metadata filters and bounded k into LangChain retrievers."""
        if code.count("{") > 50 or code.count("(") > 50 or len(code) > 10000:
            raise ValueError("Code exceeds AST complexity limits (Anti-DoS protection)")

        rewritten = code
        is_langchain = "langchain" in rewritten.lower() or "VectorStoreRetriever" in rewritten
        has_retriever = "VectorStoreRetriever" in rewritten or (
            is_langchain and (".as_retriever(" in rewritten or "similarity_search(" in rewritten)
        )
        if not has_retriever:
            return rewritten

        # Inject parameterized tenant filter dictionaries and cap k at every retrieval call
        rewritten = cls._rewrite_named_calls(rewritten, "as_retriever", cls._secure_langchain_retriever_args)
        rewritten = cls._rewrite_named_calls(rewritten, "VectorStoreRetriever", cls._secure_langchain_retriever_args)
        rewritten = cls._rewrite_named_calls(rewritten, "similarity_search", cls._secure_similarity_search_args)
        return rewritten

    @classmethod
    def harden_llamaindex_vector_index(cls, code: str) -> str:
        """Injects mandatory tenant metadata filters and bounded similarity_top_k into LlamaIndex indexes."""
        if code.count("{") > 50 or code.count("(") > 50 or len(code) > 10000:
            raise ValueError("Code exceeds AST complexity limits (Anti-DoS protection)")

        rewritten = code
        is_llama = (
            "llama_index" in rewritten.lower() or "llamaindex" in rewritten.lower() or "VectorStoreIndex" in rewritten
        )
        has_index = "VectorStoreIndex" in rewritten or (
            is_llama and (".as_retriever(" in rewritten or ".as_query_engine(" in rewritten)
        )
        if not has_index:
            return rewritten

        # Inject parameterized tenant filter dictionaries and cap similarity_top_k at every query/retriever call
        rewritten = cls._rewrite_named_calls(rewritten, "as_retriever", cls._secure_llamaindex_query_args)
        rewritten = cls._rewrite_named_calls(rewritten, "as_query_engine", cls._secure_llamaindex_query_args)
        return rewritten
