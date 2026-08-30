import json
from pathlib import Path

import yaml


def test_vulnerable_agent_configs_exist():
    base_dir = Path(__file__).parent.parent
    assert (base_dir / "prompts/system.md").exists()
    assert (base_dir / "agent/config.yaml").exists()
    assert (base_dir / "agent/tools.yaml").exists()
    assert (base_dir / "mcp/mcp_servers.json").exists()

def test_configs_load_valid_yaml_and_json():
    base_dir = Path(__file__).parent.parent
    with open(base_dir / "agent/tools.yaml", "r") as f:
        tools = yaml.safe_load(f)
    assert "tools" in tools
    assert len(tools["tools"]) >= 2

    with open(base_dir / "mcp/mcp_servers.json", "r") as f:
        mcp = json.load(f)
    assert "mcpServers" in mcp
