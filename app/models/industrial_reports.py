from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.github.pull_requests import PullRequestManager
from app.models.findings import Finding


class IndustrialReportExporter:
    """Industrial & Enterprise Audit Exporters.
    
    Generates industry-standard SARIF (OASIS standard for GitHub Code Scanning / SonarQube),
    CycloneDX AI BOM (Software/AI Bill of Materials), and SOC 2 / ISO 27001 Compliance Reports.
    """

    @classmethod
    def export_sarif(cls, findings: list[Finding], workspace_root: Path) -> dict[str, Any]:
        """Generate OASIS SARIF v2.1.0 report for native GitHub Advanced Security & CI/CD tab ingestion."""
        rules = []
        results = []
        rule_indices = {}

        for idx, f in enumerate(findings):
            tax = PullRequestManager.get_security_taxonomy_mapping(f.type.value)
            rule_id = f"OPENSHOMER/{f.type.value}"
            
            if rule_id not in rule_indices:
                rule_indices[rule_id] = len(rules)
                level = "error" if f.severity.value in ("CRITICAL", "HIGH") else "warning"
                rules.append({
                    "id": rule_id,
                    "name": f.type.value,
                    "shortDescription": {"text": f.type.value.replace("_", " ").title()},
                    "fullDescription": {"text": f.issue},
                    "defaultConfiguration": {"level": level},
                    "help": {
                        "text": f"Remediate via OpenShomer. OWASP: {tax['owasp']}, MITRE ATLAS: {tax['mitre_atlas']}, CWE: {tax['cwe']}"
                    },
                    "properties": {
                        "tags": ["security", "ai-agent", "llm-security", "owasp-llm", "mitre-atlas"],
                        "precision": "high",
                        "security-severity": "8.5" if f.severity.value in ("CRITICAL", "HIGH") else "5.0"
                    }
                })

            rule_idx = rule_indices[rule_id]
            results.append({
                "ruleId": rule_id,
                "ruleIndex": rule_idx,
                "level": "error" if f.severity.value in ("CRITICAL", "HIGH") else "warning",
                "message": {"text": f.issue},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file,
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": 1,
                            "startColumn": 1
                        }
                    }
                }]
            })

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "OpenShomer",
                        "version": "0.3.0",
                        "informationUri": "https://github.com/kavix/OpenShomer",
                        "rules": rules
                    }
                },
                "results": results
            }]
        }
        return sarif_doc

    @classmethod
    def export_ai_bom(cls, workspace_root: Path, findings: list[Finding]) -> dict[str, Any]:
        """Generate CycloneDX v1.5 / AI Bill of Materials (AIBOM) tracking models, tools, skills & MCPs."""
        components = []
        
        # Discover tools
        tools_path = workspace_root / "agent/tools.yaml"
        if tools_path.exists():
            components.append({
                "type": "data",
                "name": "agent-tools-definition",
                "version": "1.0",
                "scope": "required",
                "description": "Agent tool definitions and permission scopes"
            })

        # Discover MCPs
        mcp_path = workspace_root / "mcp/mcp_servers.json"
        if mcp_path.exists():
            components.append({
                "type": "framework",
                "name": "model-context-protocol-servers",
                "version": "1.0",
                "scope": "required",
                "description": "MCP server integrations and environment connections"
            })

        # Discover Prompt files
        prompts = list(workspace_root.rglob("*.md")) + list(workspace_root.rglob("*.prompt"))
        for p in prompts:
            components.append({
                "type": "file",
                "name": str(p.relative_to(workspace_root)),
                "description": "System instruction prompt architecture"
            })

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:openshomer-aibom-{workspace_root.name}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [{"vendor": "OpenShomer", "name": "OpenShomer AI Auditor", "version": "0.3.0"}],
                "component": {
                    "type": "application",
                    "name": workspace_root.name,
                    "version": "1.0.0"
                }
            },
            "components": components,
            "vulnerabilities": [
                {
                    "id": f.id,
                    "source": {"name": "OpenShomer"},
                    "description": f.issue,
                    "ratings": [{"severity": f.severity.value.lower()}],
                    "affects": [{"ref": f.file}]
                } for f in findings
            ]
        }
