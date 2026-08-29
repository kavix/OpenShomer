# Threat Model and Security Philosophy

OpenShomer is designed to mitigate critical vulnerabilities specific to autonomous agents and LLM configurations.

---

## Targeted Threat Vectors

1. **Over-Permissioned Tools:** Tools with unrestricted system access (raw shell, unconstrained SQL) lacking human-in-the-loop authorization gates.
2. **Direct & Indirect Prompt Injection:** Untrusted context or user input manipulating system-level agent directives.
3. **Data Exfiltration Paths:** Agents directed to forward confidential context or environment variables to external endpoints.
4. **Hardcoded Secrets in Prompts:** API keys, database credentials, or private certificates embedded directly inside agent instruction files.

---

## Core Security Tenets

- **Zero Implicit Trust:** Proposed patches are treated as untrusted until verified by deterministic policies and adversarial tests.
- **Minimal Blast Radius:** Rewrites modify only necessary permission attributes or prompt frames.
- **Deterministic Disposing:** Static checks and red-team pass/fail criteria decide PR eligibility, not heuristic scores.
