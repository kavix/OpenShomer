import json
import yaml
from pathlib import Path
from app.qoder.diff_synthesizer import DiffSynthesizer
from app.qoder.prompt_fencing import PromptFenceBuilder
from app.qoder.ide import QoderIDE


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
