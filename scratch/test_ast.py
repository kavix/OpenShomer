import ast


class XReplacer(ast.NodeTransformer):
    def __init__(self, replacement):
        self.replacement = replacement

    def visit_Name(self, node):
        if node.id == "X":
            return self.replacement
        return node


def _cap_k(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        if node.value > 50:
            return ast.Constant(value=10)
        return node
    wrap = ast.parse("min(X, 20)", mode="eval").body
    return XReplacer(node).visit(wrap)


def _wrap_filter(node):
    wrap = ast.parse("{**(X), 'tenant_id': tenant_id}", mode="eval").body
    return XReplacer(node).visit(wrap)


def secure_langchain_args(args: str) -> str:
    try:
        tree = ast.parse(f"f({args})")
        call = tree.body[0].value
    except SyntaxError:
        return args

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
                    sk_kw.value.values[i] = _wrap_filter(sk_kw.value.values[i])
                elif isinstance(key, ast.Constant) and key.value == "k":
                    has_k = True
                    sk_kw.value.values[i] = _cap_k(sk_kw.value.values[i])
            if not has_f:
                sk_kw.value.keys.append(ast.Constant(value="filter"))
                sk_kw.value.values.append(ast.parse('{"tenant_id": tenant_id}', mode="eval").body)
            if not has_k:
                sk_kw.value.keys.append(ast.Constant(value="k"))
                sk_kw.value.values.append(ast.Constant(value=10))
        else:
            wrap = ast.parse(
                "{**(X), 'filter': {**(X.get('filter', {})), 'tenant_id': tenant_id}, 'k': min(X.get('k', 10), 20)}",
                mode="eval",
            ).body
            sk_kw.value = XReplacer(sk_kw.value).visit(wrap)

    return ast.unparse(call)[2:-1]


def secure_similarity_search_args(args: str) -> str:
    try:
        tree = ast.parse(f"f({args})")
        call = tree.body[0].value
    except SyntaxError:
        return args

    f_kw = next((kw for kw in call.keywords if kw.arg == "filter"), None)
    if not f_kw:
        call.keywords.append(ast.keyword(arg="filter", value=ast.parse('{"tenant_id": tenant_id}', mode="eval").body))
    else:
        f_kw.value = _wrap_filter(f_kw.value)

    k_kw = next((kw for kw in call.keywords if kw.arg == "k"), None)
    if not k_kw:
        call.keywords.append(ast.keyword(arg="k", value=ast.Constant(value=10)))
    else:
        k_kw.value = _cap_k(k_kw.value)

    return ast.unparse(call)[2:-1]


def secure_llamaindex_args(args: str) -> str:
    try:
        tree = ast.parse(f"f({args})")
        call = tree.body[0].value
    except SyntaxError:
        return args

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
                    vsk_kw.value.values[i] = _wrap_filter(vsk_kw.value.values[i])
            if not has_f:
                vsk_kw.value.keys.append(ast.Constant(value="filter"))
                vsk_kw.value.values.append(ast.parse('{"tenant_id": tenant_id}', mode="eval").body)
        else:
            wrap = ast.parse("{**(X), 'filter': {**(X.get('filter', {})), 'tenant_id': tenant_id}}", mode="eval").body
            vsk_kw.value = XReplacer(vsk_kw.value).visit(wrap)

    tk_kw = next((kw for kw in call.keywords if kw.arg == "similarity_top_k"), None)
    if not tk_kw:
        call.keywords.append(ast.keyword(arg="similarity_top_k", value=ast.Constant(value=10)))
    else:
        tk_kw.value = _cap_k(tk_kw.value)

    return ast.unparse(call)[2:-1]


print(secure_langchain_args("search_kwargs={'filter': {'$ne': 'admin'}, 'k': 100}"))
print(secure_similarity_search_args("query, filter={'role': 'admin'}, k=sys.maxsize"))
print(secure_llamaindex_args("vector_store_kwargs=my_kwargs, similarity_top_k=500"))
