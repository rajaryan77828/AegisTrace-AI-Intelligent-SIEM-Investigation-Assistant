"""Provider-agnostic LLM client.

Talks to any hosted or local model through plain HTTPS (``requests``), so no
vendor SDK is required.  Three wire protocols cover practically every API:

* ``openai``    - OpenAI-style ``/chat/completions`` (OpenAI, Groq, OpenRouter,
                  Mistral, DeepSeek, Together, xAI, Ollama, LM Studio, vLLM, ...)
* ``anthropic`` - Anthropic ``/messages``
* ``gemini``    - Google ``generateContent``

The API key lives only in memory (Streamlit session state) and is never written
to disk, logged, or placed in exported reports.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests

from utils.security import EndpointError, redact, validate_endpoint

MAX_RESPONSE_BYTES = 2_000_000

PROVIDERS: dict[str, dict[str, Any]] = {
    "openai": {
        "label": "OpenAI", "protocol": "openai",
        "base_url": "https://api.openai.com/v1", "default_model": "gpt-4.1-mini",
        "models": ["gpt-4.1-mini", "gpt-4.1", "gpt-4o-mini", "gpt-4o"], "key_required": True,
    },
    "anthropic": {
        "label": "Anthropic (Claude)", "protocol": "anthropic",
        "base_url": "https://api.anthropic.com/v1", "default_model": "claude-sonnet-4-5",
        "models": ["claude-sonnet-4-5", "claude-haiku-4-5", "claude-opus-4-1"], "key_required": True,
    },
    "gemini": {
        "label": "Google Gemini", "protocol": "gemini",
        "base_url": "https://generativelanguage.googleapis.com/v1beta", "default_model": "gemini-2.5-flash",
        "models": ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash"], "key_required": True,
    },
    "groq": {
        "label": "Groq", "protocol": "openai",
        "base_url": "https://api.groq.com/openai/v1", "default_model": "llama-3.3-70b-versatile",
        "models": ["llama-3.3-70b-versatile", "llama-3.1-8b-instant"], "key_required": True,
    },
    "openrouter": {
        "label": "OpenRouter", "protocol": "openai",
        "base_url": "https://openrouter.ai/api/v1", "default_model": "openai/gpt-4.1-mini",
        "models": ["openai/gpt-4.1-mini", "anthropic/claude-sonnet-4.5", "google/gemini-2.5-flash"],
        "key_required": True,
    },
    "mistral": {
        "label": "Mistral", "protocol": "openai",
        "base_url": "https://api.mistral.ai/v1", "default_model": "mistral-small-latest",
        "models": ["mistral-small-latest", "mistral-large-latest"], "key_required": True,
    },
    "deepseek": {
        "label": "DeepSeek", "protocol": "openai",
        "base_url": "https://api.deepseek.com/v1", "default_model": "deepseek-chat",
        "models": ["deepseek-chat", "deepseek-reasoner"], "key_required": True,
    },
    "together": {
        "label": "Together AI", "protocol": "openai",
        "base_url": "https://api.together.xyz/v1", "default_model": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "models": ["meta-llama/Llama-3.3-70B-Instruct-Turbo"], "key_required": True,
    },
    "xai": {
        "label": "xAI (Grok)", "protocol": "openai",
        "base_url": "https://api.x.ai/v1", "default_model": "grok-3-mini",
        "models": ["grok-3-mini", "grok-3"], "key_required": True,
    },
    "ollama": {
        "label": "Ollama (local)", "protocol": "openai",
        "base_url": "http://localhost:11434/v1", "default_model": "llama3.1",
        "models": ["llama3.1", "qwen2.5", "mistral"], "key_required": False,
    },
    "lmstudio": {
        "label": "LM Studio (local)", "protocol": "openai",
        "base_url": "http://localhost:1234/v1", "default_model": "local-model",
        "models": [], "key_required": False,
    },
    "custom": {
        "label": "Custom endpoint", "protocol": "openai",
        "base_url": "", "default_model": "", "models": [], "key_required": False,
    },
}

PROTOCOL_LABELS = {
    "openai": "OpenAI-compatible (/chat/completions)",
    "anthropic": "Anthropic (/messages)",
    "gemini": "Google Gemini (generateContent)",
}


@dataclass
class LLMConfig:
    provider: str = "openai"
    protocol: str = "openai"
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4.1-mini"
    api_key: str = ""
    temperature: float = 0.1
    max_tokens: int = 1800
    timeout: int = 60
    auth_header: str = ""       # custom endpoints: e.g. "X-API-Key"; empty = protocol default
    auth_prefix: str = ""       # custom endpoints: e.g. "Bearer "
    extra_headers: dict[str, str] = field(default_factory=dict)

    @property
    def key_required(self) -> bool:
        return PROVIDERS.get(self.provider, {}).get("key_required", False)

    def is_ready(self) -> bool:
        if not self.base_url or not self.model:
            return False
        return bool(self.api_key) or not self.key_required

    def public_dict(self) -> dict[str, Any]:
        """Config safe to show / export (never contains the key)."""
        return {
            "provider": self.provider, "protocol": self.protocol,
            "base_url": self.base_url, "model": self.model,
        }


class LLMError(RuntimeError):
    """User-presentable LLM failure (secrets already redacted)."""


def preset_config(provider: str, **overrides: Any) -> LLMConfig:
    p = PROVIDERS.get(provider, PROVIDERS["custom"])
    cfg = LLMConfig(
        provider=provider, protocol=p["protocol"],
        base_url=p["base_url"], model=p["default_model"],
    )
    for k, v in overrides.items():
        if v not in (None, ""):
            setattr(cfg, k, v)
    return cfg


# ── environment / .env loading ────────────────────────────────────────────

def load_dotenv(path: str | Path | None = None) -> None:
    """Minimal .env loader (no dependency). Existing env vars win."""
    path = Path(path) if path else Path(__file__).parent / ".env"
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


def config_from_env() -> LLMConfig:
    """Build the default config from environment / Streamlit secrets."""
    load_dotenv()
    provider = os.getenv("AEGIS_PROVIDER", "openai").lower()
    if provider not in PROVIDERS:
        provider = "custom"
    key = os.getenv("AEGIS_API_KEY") or os.getenv("OPENAI_API_KEY", "")
    model = os.getenv("AEGIS_MODEL") or os.getenv("OPENAI_MODEL", "")
    return preset_config(provider, api_key=key, model=model, base_url=os.getenv("AEGIS_BASE_URL", ""))


# ── transport ─────────────────────────────────────────────────────────────

def _headers(cfg: LLMConfig) -> dict[str, str]:
    h = {"Content-Type": "application/json", "User-Agent": "AegisTraceAI/2.1"}
    key = cfg.api_key
    if cfg.auth_header:
        if key:
            h[cfg.auth_header] = f"{cfg.auth_prefix}{key}"
    elif cfg.protocol == "anthropic":
        h["x-api-key"] = key
        h["anthropic-version"] = "2023-06-01"
    elif cfg.protocol == "gemini":
        h["x-goog-api-key"] = key
    elif key:
        h["Authorization"] = f"Bearer {key}"
    if cfg.protocol == "anthropic" and "anthropic-version" not in h:
        h["anthropic-version"] = "2023-06-01"
    h.update({k: v for k, v in cfg.extra_headers.items() if k and v})
    return h


def _build_request(cfg: LLMConfig, system: str, user: str, *, max_tokens: int) -> tuple[str, dict]:
    base = cfg.base_url.rstrip("/")
    if cfg.protocol == "anthropic":
        return f"{base}/messages", {
            "model": cfg.model, "max_tokens": max_tokens, "temperature": cfg.temperature,
            "system": system, "messages": [{"role": "user", "content": user}],
        }
    if cfg.protocol == "gemini":
        return f"{base}/models/{cfg.model}:generateContent", {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {"temperature": cfg.temperature, "maxOutputTokens": max_tokens},
        }
    body: dict[str, Any] = {
        "model": cfg.model, "temperature": cfg.temperature,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
    }
    # OpenAI's newer models renamed max_tokens and reject custom temperature.
    if "api.openai.com" in base and cfg.model.lower().startswith(("o1", "o3", "o4", "gpt-5")):
        body.pop("temperature")
        body["max_completion_tokens"] = max_tokens
    else:
        body["max_tokens"] = max_tokens
    return f"{base}/chat/completions", body


def _extract_text(cfg: LLMConfig, data: dict) -> str:
    try:
        if cfg.protocol == "anthropic":
            return "".join(b.get("text", "") for b in data["content"] if b.get("type") == "text")
        if cfg.protocol == "gemini":
            parts = data["candidates"][0]["content"]["parts"]
            return "".join(p.get("text", "") for p in parts)
        content = data["choices"][0]["message"]["content"]
        if isinstance(content, list):  # some servers return content blocks
            content = "".join(c.get("text", "") for c in content if isinstance(c, dict))
        return content or ""
    except (KeyError, IndexError, TypeError) as exc:
        raise LLMError("The provider returned an unexpected response format. "
                       "Check the protocol setting for this endpoint.") from exc


def complete(cfg: LLMConfig, system: str, user: str, *, max_tokens: int | None = None) -> str:
    """Send one prompt to the configured provider and return the text reply."""
    if not cfg.is_ready():
        raise LLMError("LLM is not configured: base URL, model and (if required) API key are needed.")
    try:
        validate_endpoint(cfg.base_url)
    except EndpointError as exc:
        raise LLMError(str(exc)) from exc

    url, body = _build_request(cfg, system, user, max_tokens=max_tokens or cfg.max_tokens)
    try:
        resp = requests.post(
            url, json=body, headers=_headers(cfg), timeout=cfg.timeout,
            allow_redirects=False, stream=True,
        )
        raw = resp.raw.read(MAX_RESPONSE_BYTES + 1, decode_content=True)
    except requests.Timeout as exc:
        raise LLMError(f"Request timed out after {cfg.timeout}s.") from exc
    except requests.RequestException as exc:
        raise LLMError(redact(f"Could not reach the endpoint: {exc.__class__.__name__}", cfg.api_key)) from exc

    if len(raw) > MAX_RESPONSE_BYTES:
        raise LLMError("Provider response was too large and was discarded.")
    if 300 <= resp.status_code < 400:
        raise LLMError("The endpoint attempted a redirect, which is blocked for safety.")
    if resp.status_code >= 400:
        snippet = redact(raw[:400].decode("utf-8", "replace"), cfg.api_key)
        hint = {401: " (check the API key)", 403: " (key lacks access)", 404: " (check base URL / model name)",
                429: " (rate limited or out of quota)"}.get(resp.status_code, "")
        raise LLMError(f"HTTP {resp.status_code}{hint}: {snippet}")
    try:
        import json
        data = json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        raise LLMError("The endpoint did not return JSON. Check the base URL.") from exc
    text = _extract_text(cfg, data).strip()
    if not text:
        raise LLMError("The model returned an empty response.")
    return text


def test_connection(cfg: LLMConfig) -> tuple[bool, str]:
    """Cheap round-trip used by the 'Test connection' button."""
    try:
        complete(cfg, "Reply with the single word: ok", "ping", max_tokens=16)
        return True, "Connected. The model responded."
    except LLMError as exc:
        return False, str(exc)
