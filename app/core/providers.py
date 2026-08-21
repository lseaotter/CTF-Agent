"""Provider configuration and small HTTP clients for CyberGem.

Credentials are read from process environment variables only. This module
never writes keys to disk and never exposes them in public status payloads.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import time
from typing import Any, Iterable

import httpx

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional dependency for library users
    load_dotenv = None


if load_dotenv is not None:
    load_dotenv(Path(__file__).resolve().parents[2] / ".env", override=False)


_KEY_PATTERN = re.compile(r"sk-[A-Za-z0-9_-]{8,}", re.IGNORECASE)


class ProviderError(RuntimeError):
    """A sanitized provider failure safe to display in the local UI."""


def api_endpoint(base_url: str, resource: str) -> str:
    """Join a provider base URL with a v1 resource without duplicating /v1."""
    normalized = base_url.rstrip("/")
    if normalized.endswith("/v1"):
        return f"{normalized}/{resource.lstrip('/')}"
    return f"{normalized}/v1/{resource.lstrip('/')}"


def _first_environment_value(names: Iterable[str]) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return None


def _sanitize(value: str, secret: str | None = None) -> str:
    sanitized = value
    if secret:
        sanitized = sanitized.replace(secret, "[redacted]")
    return _KEY_PATTERN.sub("[redacted]", sanitized)


@dataclass(frozen=True)
class ProviderConfig:
    key: str
    label: str
    protocol: str
    base_url: str
    model: str
    api_key_names: tuple[str, ...]

    @property
    def api_key(self) -> str | None:
        return _first_environment_value(self.api_key_names)

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    @property
    def models_url(self) -> str:
        return api_endpoint(self.base_url, "models")

    def public_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "protocol": self.protocol,
            "base_url": self.base_url,
            "model": self.model,
            "configured": self.configured,
        }


def deepseek_config() -> ProviderConfig:
    return ProviderConfig(
        key="deepseek",
        label="DeepSeek",
        protocol="openai-chat",
        base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
        model=os.getenv("DEEPSEEK_MODEL", "deepseek-chat"),
        api_key_names=("DEEPSEEK_API_KEY",),
    )


def claude_config() -> ProviderConfig:
    return ProviderConfig(
        key="claude",
        label="Anthropic Claude",
        protocol="anthropic-messages",
        base_url=os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com"),
        model=os.getenv(
            "ANTHROPIC_MODEL",
            os.getenv("ANTHROPIC_DEFAULT_FABLE_MODEL", "claude-3-5-sonnet-20241022"),
        ),
        api_key_names=("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"),
    )


def all_provider_configs() -> tuple[ProviderConfig, ProviderConfig]:
    return deepseek_config(), claude_config()


def _response_error(response: httpx.Response, config: ProviderConfig) -> ProviderError:
    detail = response.text[:500]
    try:
        payload = response.json()
        if isinstance(payload, dict):
            error = payload.get("error", payload)
            if isinstance(error, dict):
                detail = str(error.get("message") or error.get("detail") or detail)
            else:
                detail = str(error)
    except (ValueError, json.JSONDecodeError):
        pass
    return ProviderError(
        f"{config.label} returned HTTP {response.status_code}: "
        f"{_sanitize(detail, config.api_key)}"
    )


def probe_provider(config: ProviderConfig, timeout: float = 20.0) -> dict[str, Any]:
    started = time.perf_counter()
    if not config.api_key:
        return {
            **config.public_dict(),
            "ok": False,
            "status": "not_configured",
            "latency_ms": None,
            "model_available": False,
            "error": "Credential is not loaded in this process.",
        }

    headers = {
        "Authorization": f"Bearer {config.api_key}",
        "x-api-key": config.api_key,
    }
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            response = client.get(config.models_url, headers=headers)
        latency_ms = round((time.perf_counter() - started) * 1000)
        if response.status_code != 200:
            raise _response_error(response, config)

        payload = response.json()
        models = payload.get("data", []) if isinstance(payload, dict) else []
        model_ids = {
            item.get("id")
            for item in models
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        }
        return {
            **config.public_dict(),
            "ok": True,
            "status": "available",
            "latency_ms": latency_ms,
            "model_available": config.model in model_ids,
            "available_model_count": len(model_ids),
            "error": None,
        }
    except (httpx.HTTPError, ProviderError, ValueError) as exc:
        return {
            **config.public_dict(),
            "ok": False,
            "status": "unavailable",
            "latency_ms": round((time.perf_counter() - started) * 1000),
            "model_available": False,
            "error": _sanitize(str(exc), config.api_key),
        }


def call_deepseek(
    prompt: str,
    *,
    system_prompt: str | None = None,
    temperature: float = 0.2,
    max_tokens: int = 2000,
    config: ProviderConfig | None = None,
) -> str:
    selected = config or deepseek_config()
    if not selected.api_key:
        raise ProviderError("DEEPSEEK_API_KEY is not loaded in this process.")

    messages: list[dict[str, str]] = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    try:
        with httpx.Client(timeout=120.0, follow_redirects=True) as client:
            response = client.post(
                api_endpoint(selected.base_url, "chat/completions"),
                headers={
                    "Authorization": f"Bearer {selected.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": selected.model,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                },
            )
        if response.status_code != 200:
            raise _response_error(response, selected)
        return response.json()["choices"][0]["message"]["content"]
    except httpx.HTTPError as exc:
        raise ProviderError(_sanitize(str(exc), selected.api_key)) from exc


def call_claude(
    prompt: str,
    *,
    system_prompt: str | None = None,
    temperature: float = 0.2,
    max_tokens: int = 2000,
    config: ProviderConfig | None = None,
) -> str:
    selected = config or claude_config()
    if not selected.api_key:
        raise ProviderError(
            "ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN is not loaded in this process."
        )

    payload: dict[str, Any] = {
        "model": selected.model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if system_prompt:
        payload["system"] = system_prompt

    try:
        with httpx.Client(timeout=120.0, follow_redirects=True) as client:
            response = client.post(
                api_endpoint(selected.base_url, "messages"),
                headers={
                    "x-api-key": selected.api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
        if response.status_code != 200:
            raise _response_error(response, selected)
        return "".join(
            block.get("text", "")
            for block in response.json().get("content", [])
            if isinstance(block, dict) and block.get("type") == "text"
        )
    except httpx.HTTPError as exc:
        raise ProviderError(_sanitize(str(exc), selected.api_key)) from exc


def parse_json_object(content: str) -> dict[str, Any]:
    """Parse a model response that may wrap JSON in a Markdown fence."""
    stripped = content.strip()
    fence = chr(96) * 3
    if fence in stripped:
        pattern = rf"{re.escape(fence)}(?:json)?\s*(\{{.*?\}})\s*{re.escape(fence)}"
        match = re.search(pattern, stripped, re.DOTALL)
        if match:
            stripped = match.group(1)
    else:
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start >= 0 and end > start:
            stripped = stripped[start : end + 1]
    parsed = json.loads(stripped)
    if not isinstance(parsed, dict):
        raise ValueError("Provider response did not contain a JSON object.")
    return parsed
