"""LLM管理器 - 多模型支持"""

from __future__ import annotations

import os
from typing import Literal

import httpx
import yaml
from pathlib import Path

from app.core.providers import api_endpoint

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional dependency for library users
    load_dotenv = None


class LLMConfig:
    """LLM配置"""

    def __init__(self, config_path: Path | None = None):
        if load_dotenv is not None:
            load_dotenv(Path(__file__).resolve().parents[2] / ".env", override=False)
        if config_path is None:
            config_path = Path(__file__).parent.parent.parent / "configs" / "models.yaml"

        if not config_path.exists():
            config_path = config_path.parent / "models.yaml.example"

        with open(config_path, "r", encoding="utf-8") as f:
            self.config = yaml.safe_load(f)

    def get_provider(self, name: str) -> dict:
        """获取provider配置"""
        return self.config["providers"].get(name, {})

    def get_default_hypothesis_model(self) -> str:
        """获取默认假设生成模型"""
        return self.config["default"]["hypothesis_model"]

    def get_default_poc_model(self) -> str:
        """获取默认PoC构造模型"""
        return self.config["default"]["poc_model"]


class LLMManager:
    """LLM管理器"""

    def __init__(self, config: LLMConfig | None = None):
        self.config = config or LLMConfig()

    async def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        model: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> str:
        """生成文本"""
        # 如果未指定模型，使用默认模型
        if model is None:
            model = self.config.get_default_hypothesis_model()

        provider_config = self.config.get_provider(model)
        if not provider_config:
            raise ValueError(f"未找到模型配置: {model}")

        provider_type = provider_config["provider"]

        if provider_type == "openai":
            return await self._generate_openai(
                prompt,
                system_prompt,
                provider_config,
                temperature,
                max_tokens,
            )
        elif provider_type == "anthropic":
            return await self._generate_anthropic(
                prompt,
                system_prompt,
                provider_config,
                temperature,
                max_tokens,
            )
        elif provider_type == "deepseek":
            return await self._generate_deepseek(
                prompt,
                system_prompt,
                provider_config,
                temperature,
                max_tokens,
            )
        else:
            raise ValueError(f"不支持的provider类型: {provider_type}")

    async def _generate_openai(
        self,
        prompt: str,
        system_prompt: str | None,
        config: dict,
        temperature: float,
        max_tokens: int,
    ) -> str:
        """使用OpenAI API生成"""
        api_key = os.getenv(config["api_key_env"])
        if not api_key:
            raise ValueError(f"未设置环境变量: {config['api_key_env']}")

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        async with httpx.AsyncClient() as client:
            response = await client.post(
                api_endpoint(config["base_url"], "chat/completions"),
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": config["model"],
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                },
                timeout=60.0,
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]

    async def _generate_anthropic(
        self,
        prompt: str,
        system_prompt: str | None,
        config: dict,
        temperature: float,
        max_tokens: int,
    ) -> str:
        """使用Anthropic API生成"""
        api_key = os.getenv(config["api_key_env"])
        if not api_key:
            raise ValueError(f"未设置环境变量: {config['api_key_env']}")

        async with httpx.AsyncClient() as client:
            payload = {
                "model": config["model"],
                "messages": [{"role": "user", "content": prompt}],
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            if system_prompt:
                payload["system"] = system_prompt

            response = await client.post(
                api_endpoint(
                    config.get("base_url", "https://api.anthropic.com"),
                    "messages",
                ),
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=60.0,
            )
            response.raise_for_status()
            data = response.json()
            return data["content"][0]["text"]

    async def _generate_deepseek(
        self,
        prompt: str,
        system_prompt: str | None,
        config: dict,
        temperature: float,
        max_tokens: int,
    ) -> str:
        """使用DeepSeek API生成（兼容OpenAI格式）"""
        api_key = os.getenv(config["api_key_env"])
        if not api_key:
            raise ValueError(f"未设置环境变量: {config['api_key_env']}")

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        async with httpx.AsyncClient() as client:
            response = await client.post(
                api_endpoint(config["base_url"], "chat/completions"),
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": config["model"],
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                },
                timeout=60.0,
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]

    def estimate_cost(self, prompt: str, response: str, model: str) -> float:
        """估算成本"""
        provider_config = self.config.get_provider(model)
        if not provider_config:
            return 0.0

        # 简单估算：每个字符约0.25个token
        prompt_tokens = len(prompt) // 4
        response_tokens = len(response) // 4
        total_tokens = prompt_tokens + response_tokens

        cost_per_1k = provider_config.get("cost_per_1k_tokens", 0.0)
        return (total_tokens / 1000) * cost_per_1k
