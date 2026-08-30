# Static LLM security rules

OpenShomer's deterministic checker reports structured findings for four OWASP LLM categories before an agent workspace is executed:

- **LLM01 — Direct prompt injection:** user-controlled placeholders must be inside an explicit untrusted-input boundary.
- **LLM02 — Sensitive information disclosure:** prompts must not contain credentials or instructions to reveal secrets and personal identifiers.
- **LLM06 — Excessive agency:** shell, subprocess, SQL, and unrestricted filesystem tools require approval or parameter bounds.
- **LLM07 — System prompt leakage:** system instructions must explicitly forbid disclosure of hidden instructions.

The checker is intentionally conservative and deterministic. It reports findings for review; it does not claim that a prompt is safe merely because no pattern matched.
