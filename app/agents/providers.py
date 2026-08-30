import os
import json
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
import httpx


class LLMProvider(ABC):
    """Abstract base class for LLM reasoning backbones in OpenShomer."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key
        self.model = model

    @abstractmethod
    def generate(self, prompt: str, system_prompt: Optional[str] = None, temperature: float = 0.2) -> str:
        """Synchronously generate a completion given a prompt and optional system prompt."""
        pass


class AlibabaQwenProvider(LLMProvider):
    """Alibaba Cloud Model Studio (Bailian / DashScope) Qwen LLM Provider.
    
    Supports Qwen reasoning models: qwen-max, qwen-plus, qwen-turbo, qwen-coder-plus.
    """

    DEFAULT_MODEL = "qwen-plus"
    BASE_URL = os.getenv("DASHSCOPE_BASE_URL", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1")

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = 30.0,
    ):
        key = api_key or os.getenv("DASHSCOPE_API_KEY") or os.getenv("ALIBABA_CLOUD_API_KEY") or os.getenv("ALIBABA_API_KEY")
        super().__init__(api_key=key, model=model or self.DEFAULT_MODEL)
        self.base_url = base_url or self.BASE_URL
        self.timeout = timeout

    def generate(self, prompt: str, system_prompt: Optional[str] = None, temperature: float = 0.2) -> str:
        if not self.api_key:
            raise ValueError("Alibaba Cloud DashScope API key is required (set DASHSCOPE_API_KEY or ALIBABA_CLOUD_API_KEY).")

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }

        url = f"{self.base_url.rstrip('/')}/chat/completions"

        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()
            choices = data.get("choices", [])
            if choices and "message" in choices[0]:
                return choices[0]["message"].get("content", "")
            return ""


class OpenAIProvider(LLMProvider):
    """OpenAI GPT models provider."""

    DEFAULT_MODEL = "gpt-4o"

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None, timeout: float = 30.0):
        key = api_key or os.getenv("OPENAI_API_KEY")
        super().__init__(api_key=key, model=model or self.DEFAULT_MODEL)
        self.timeout = timeout

    def generate(self, prompt: str, system_prompt: Optional[str] = None, temperature: float = 0.2) -> str:
        if not self.api_key:
            raise ValueError("OpenAI API key is required (set OPENAI_API_KEY).")

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {"model": self.model, "messages": messages, "temperature": temperature}

        with httpx.Client(timeout=self.timeout) as client:
            response = client.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]


class GeminiProvider(LLMProvider):
    """Google Gemini models provider."""

    DEFAULT_MODEL = "gemini-1.5-flash"

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None, timeout: float = 30.0):
        key = api_key or os.getenv("GEMINI_API_KEY")
        super().__init__(api_key=key, model=model or self.DEFAULT_MODEL)
        self.timeout = timeout

    def generate(self, prompt: str, system_prompt: Optional[str] = None, temperature: float = 0.2) -> str:
        if not self.api_key:
            raise ValueError("Gemini API key is required (set GEMINI_API_KEY).")

        contents = []
        if system_prompt:
            contents.append({"role": "user", "parts": [{"text": f"System Instructions: {system_prompt}"}]})
            contents.append({"role": "model", "parts": [{"text": "Understood. I will abide by these instructions."}]})
        contents.append({"role": "user", "parts": [{"text": prompt}]})

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        payload = {"contents": contents, "generationConfig": {"temperature": temperature}}

        with httpx.Client(timeout=self.timeout) as client:
            response = client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            candidates = data.get("candidates", [])
            if candidates:
                return candidates[0]["content"]["parts"][0]["text"]
            return ""


def get_llm_provider(
    provider_name: Optional[str] = None,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Optional[LLMProvider]:
    """Auto-detects or initializes the requested LLM provider."""
    name = (provider_name or os.getenv("OPENSHOMER_LLM_PROVIDER", "")).lower()

    if name in ("alibaba", "qwen", "dashscope", "bailian"):
        return AlibabaQwenProvider(api_key=api_key, model=model)
    elif name == "openai":
        return OpenAIProvider(api_key=api_key, model=model)
    elif name in ("gemini", "google"):
        return GeminiProvider(api_key=api_key, model=model)

    # Auto-detection from environment if not explicitly set
    if os.getenv("DASHSCOPE_API_KEY") or os.getenv("ALIBABA_CLOUD_API_KEY") or os.getenv("ALIBABA_API_KEY"):
        return AlibabaQwenProvider(api_key=api_key, model=model)
    elif os.getenv("OPENAI_API_KEY"):
        return OpenAIProvider(api_key=api_key, model=model)
    elif os.getenv("GEMINI_API_KEY"):
        return GeminiProvider(api_key=api_key, model=model)

    return None
