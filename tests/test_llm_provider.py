import os
import json
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from typer.testing import CliRunner

from app.agents.providers import (
    AlibabaQwenProvider,
    OpenAIProvider,
    GeminiProvider,
    get_llm_provider,
    LLMProvider,
)
from app.agents.investigator import InvestigationAgent
from app.agents.remediation import RemediationEngine
from app.models.findings import Finding, FindingType, Severity
from app.cli import app


class MockProvider(LLMProvider):
    def __init__(self, response_text: str = "Mocked LLM reasoning"):
        super().__init__(api_key="mock_key", model="mock-model")
        self.response_text = response_text

    def generate(self, prompt: str, system_prompt=None, temperature: float = 0.2) -> str:
        return self.response_text


def test_alibaba_qwen_provider_init():
    provider = AlibabaQwenProvider(api_key="test_dashscope_key", model="qwen-max")
    assert provider.api_key == "test_dashscope_key"
    assert provider.model == "qwen-max"
    assert "compatible-mode/v1" in provider.base_url


def test_alibaba_qwen_provider_missing_key():
    with patch.dict(os.environ, {}, clear=True):
        provider = AlibabaQwenProvider(api_key=None)
        with pytest.raises(ValueError, match="DashScope API key is required"):
            provider.generate("Test prompt")


def test_alibaba_qwen_provider_generate_success():
    provider = AlibabaQwenProvider(api_key="sk-test-12345", model="qwen-plus")

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "Alibaba Cloud Qwen: Vulnerability diagnosed successfully."
                }
            }
        ]
    }

    with patch("httpx.Client.post", return_value=mock_response) as mock_post:
        result = provider.generate("Analyze tool permissions", system_prompt="You are a security AI.")
        assert "Alibaba Cloud Qwen" in result
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert kwargs["json"]["model"] == "qwen-plus"
        assert kwargs["headers"]["Authorization"] == "Bearer sk-test-12345"


def test_get_llm_provider_auto_detect():
    # Alibaba Cloud Detection
    with patch.dict(os.environ, {"DASHSCOPE_API_KEY": "sk-dashscope-key"}, clear=True):
        provider = get_llm_provider()
        assert isinstance(provider, AlibabaQwenProvider)
        assert provider.api_key == "sk-dashscope-key"

    # Explicit Alibaba provider
    provider_explicit = get_llm_provider(provider_name="alibaba", api_key="explicit_key", model="qwen-turbo")
    assert isinstance(provider_explicit, AlibabaQwenProvider)
    assert provider_explicit.model == "qwen-turbo"

    # OpenAI Detection
    with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-openai-key"}, clear=True):
        provider_openai = get_llm_provider()
        assert isinstance(provider_openai, OpenAIProvider)

    # None if no keys configured
    with patch.dict(os.environ, {}, clear=True):
        assert get_llm_provider() is None


def test_investigator_and_remediator_with_qwen_provider(tmp_path):
    mock_provider = MockProvider("Enhanced Qwen security boundary")
    investigator = InvestigationAgent(tmp_path, llm_provider=mock_provider)
    remediator = RemediationEngine(tmp_path, llm_provider=mock_provider)

    finding = Finding(
        id="SHOMER-001",
        type=FindingType.OVER_PERMISSIONED_TOOL,
        severity=Severity.HIGH,
        file="agent/tools.yaml",
        tool="run_shell",
        issue="Unrestricted shell execution",
        repository="demo/vulnerable-agent",
    )

    result = investigator.investigate(finding)
    assert result.finding_id == "SHOMER-001"
    assert investigator.llm_provider == mock_provider
    assert remediator.llm_provider == mock_provider


def test_cli_fix_with_alibaba_provider_flag():
    runner = CliRunner()
    result = runner.invoke(app, [
        "fix",
        "demo/vulnerable-agent",
        "--provider", "alibaba",
        "--model", "qwen-plus",
        "--api-key", "mock_dashscope_key"
    ])
    assert result.exit_code == 0
    assert "Active LLM Provider: AlibabaQwenProvider (qwen-plus)" in result.stdout
