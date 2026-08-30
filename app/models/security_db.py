import json
from pathlib import Path
from typing import Any


class SecurityBenchmarkDatabase:
    """Standardized AI Security Taxonomy and Knowledge Base.
    
    Integrates MITRE ATLAS, OWASP LLM Top 10, NIST AI RMF, and CWE databases
    into unified threat intelligence for AI agents.
    """

    TAXONOMY_FILE = Path(__file__).parent.parent.parent / "data/security_knowledge_base.json"

    @classmethod
    def get_standardized_databases(cls) -> dict[str, Any]:
        return {
            "standards": [
                {
                    "framework": "MITRE ATLAS",
                    "version": "4.0.0",
                    "description": "Adversarial Threat Landscape for Artificial-Intelligence Systems",
                    "tactics": [
                        {"id": "AML.TA0000", "name": "Initial Access", "techniques": ["AML.T0051: LLM Direct Prompt Injection", "AML.T0054: LLM Jailbreak"]},
                        {"id": "AML.TA0001", "name": "Execution", "techniques": ["AML.T0053: LLM Prompt Injection via Indirect Data", "AML.T0043: Unbounded Tool Invocation"]},
                        {"id": "AML.TA0002", "name": "Persistence", "techniques": ["AML.T0048: Malicious Agent Skill Poisoning"]},
                        {"id": "AML.TA0003", "name": "Privilege Escalation", "techniques": ["AML.T0052: Autonomous Agent Goal Hijacking"]},
                        {"id": "AML.TA0004", "name": "Defense Evasion", "techniques": ["AML.T0055: Multi-Language / Token Obfuscation"]},
                        {"id": "AML.TA0005", "name": "Credential Access", "techniques": ["AML.T0056: System Prompt Key Extraction"]},
                        {"id": "AML.TA0006", "name": "Exfiltration", "techniques": ["AML.T0044: Out-of-Band Markdown Exfiltration", "AML.T0045: SSRF Tool Egress"]},
                        {"id": "AML.TA0007", "name": "Impact", "techniques": ["AML.T0046: Database Drop / Resource Exhaustion", "AML.T0047: Financial Transaction Draining"]}
                    ]
                },
                {
                    "framework": "OWASP LLM Top 10",
                    "version": "2025/2026",
                    "description": "Open Web Application Security Project - LLM & GenAI Security Standard",
                    "categories": [
                        {"id": "LLM01", "name": "Prompt Injection", "risk": "CRITICAL", "description": "Direct and indirect user payload manipulation of LLM system directives."},
                        {"id": "LLM02", "name": "Sensitive Information Disclosure", "risk": "HIGH", "description": "Leakage of proprietary prompts, PII, API tokens, or secrets."},
                        {"id": "LLM03", "name": "Supply Chain Vulnerabilities", "risk": "HIGH", "description": "Compromised third-party MCP servers, untrusted Python packages, and models."},
                        {"id": "LLM04", "name": "Data and Model Poisoning", "risk": "HIGH", "description": "Tampered fine-tuning data, malicious skill files, and poisoned RAG embeddings."},
                        {"id": "LLM05", "name": "Improper Output Handling", "risk": "HIGH", "description": "Unsanitized LLM generation directly executed by downstream subshells or browsers."},
                        {"id": "LLM06", "name": "Excessive Agency", "risk": "CRITICAL", "description": "Over-permissioned tool access, missing human-in-the-loop gates, and unbounded actions."},
                        {"id": "LLM07", "name": "System Prompt Leakage", "risk": "MEDIUM", "description": "Extraction of internal instructions, guardrails, and system meta-prompts."},
                        {"id": "LLM08", "name": "Vector and Embedding Weaknesses", "risk": "MEDIUM", "description": "Adversarial semantic injections poisoning vector database similarity searches."},
                        {"id": "LLM09", "name": "Misinformation", "risk": "MEDIUM", "description": "Hallucinated factual claims causing business or operational damage."},
                        {"id": "LLM10", "name": "Unbounded Consumption (DoS)", "risk": "HIGH", "description": "Infinite reasoning loops, resource exhaustion, and denial of wallet."}
                    ]
                },
                {
                    "framework": "NIST AI RMF",
                    "version": "1.0",
                    "description": "NIST Artificial Intelligence Risk Management Framework",
                    "functions": [
                        {"id": "GOVERN", "focus": "Cultivate risk management culture and transparent guardrails."},
                        {"id": "MAP", "focus": "Contextualize AI risks, excessive agency, and threat surface."},
                        {"id": "MEASURE", "focus": "Adversarial red-team benchmarking (1,000+ suites)."},
                        {"id": "MANAGE", "focus": "Automated patch synthesis, least-privilege scoping, and PR deployment."}
                    ]
                },
                {
                    "framework": "CWE (Common Weakness Enumeration)",
                    "version": "4.14",
                    "mappings": [
                        {"cwe_id": "CWE-78", "name": "OS Command Injection", "agent_relevance": "Unrestricted shell execution tools and backticks"},
                        {"cwe_id": "CWE-89", "name": "SQL Injection", "agent_relevance": "Unbounded database tools executing raw string queries"},
                        {"cwe_id": "CWE-918", "name": "Server-Side Request Forgery (SSRF)", "agent_relevance": "Agent web browsing tools accessing internal metadata endpoints"},
                        {"cwe_id": "CWE-22", "name": "Path Traversal", "agent_relevance": "MCP filesystem servers allowing dot-dot-slash directory traversal"},
                        {"cwe_id": "CWE-798", "name": "Use of Hardcoded Credentials", "agent_relevance": "Plaintext API keys in mcp_servers.json or prompt files"},
                        {"cwe_id": "CWE-862", "name": "Missing Authorization", "agent_relevance": "Missing human-in-the-loop approval on destructive tools"}
                    ]
                }
            ]
        }

    @classmethod
    def load_or_init(cls) -> dict[str, Any]:
        cls.TAXONOMY_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = cls.get_standardized_databases()
        with open(cls.TAXONOMY_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return data


if __name__ == "__main__":
    db = SecurityBenchmarkDatabase.load_or_init()
    print(f"Loaded {len(db['standards'])} Standardized Security Knowledge Bases (MITRE ATLAS, OWASP LLM, NIST AI RMF, CWE).")
