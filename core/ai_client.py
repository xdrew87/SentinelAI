"""
core/ai_client.py – Unified AI provider abstraction.

Supports: OpenAI (GPT-*), Anthropic (Claude), Google (Gemini), Ollama (local).
API keys are retrieved from encrypted config storage.
"""

from __future__ import annotations

import json
import logging
from typing import Generator, Optional, TYPE_CHECKING

import requests

if TYPE_CHECKING:
    from core.config import Config

log = logging.getLogger(__name__)

_TIMEOUT = 120


class AIClient:
    """
    Unified interface to multiple AI providers.

    Usage:
        client = AIClient(config)
        response = client.complete("Summarise this incident…")
    """

    def __init__(self, config: "Config") -> None:
        self._config = config

    # ── Public API ────────────────────────────────────────────────────────

    def complete(
        self,
        prompt: str,
        system: str = "You are SentinelAI, an expert DFIR and cybersecurity analyst assistant.",
        model: Optional[str] = None,
        provider: Optional[str] = None,
        stream: bool = False,
    ) -> str:
        """
        Send a prompt to the configured AI provider and return the response.

        Args:
            prompt:   The user prompt.
            system:   System/context message.
            model:    Override the configured model.
            provider: Override the configured provider.
            stream:   If True, returns accumulated streamed text.

        Returns:
            The AI response text.
        """
        p = provider or self._config.get("ai_provider", "openai")
        m = model or self._config.get("ai_model", "gpt-4o")

        if p == "openai":
            return self._openai(prompt, system, m)
        elif p == "anthropic":
            return self._anthropic(prompt, system, m)
        elif p == "gemini":
            return self._gemini(prompt, system, m)
        elif p == "ollama":
            return self._ollama(prompt, system, m)
        else:
            raise ValueError(f"Unknown AI provider: {p!r}")

    def test_connection(self, provider: str) -> tuple[bool, str]:
        """Test connectivity to a provider. Returns (ok, message)."""
        try:
            resp = self.complete(
                "Reply with exactly: OK",
                provider=provider,
            )
            return True, resp.strip()
        except Exception as exc:
            return False, str(exc)

    # ── Providers ─────────────────────────────────────────────────────────

    def _openai(self, prompt: str, system: str, model: str) -> str:
        api_key = self._config.get_secret("openai_api_key")
        if not api_key:
            raise RuntimeError("OpenAI API key not configured. Go to Settings → AI.")
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 4096,
        }
        resp = requests.post(url, headers=headers, json=payload, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    def _anthropic(self, prompt: str, system: str, model: str) -> str:
        api_key = self._config.get_secret("anthropic_api_key")
        if not api_key:
            raise RuntimeError("Anthropic API key not configured. Go to Settings → AI.")
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "max_tokens": 4096,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }
        resp = requests.post(url, headers=headers, json=payload, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        return data["content"][0]["text"]

    def _gemini(self, prompt: str, system: str, model: str) -> str:
        api_key = self._config.get_secret("gemini_api_key")
        if not api_key:
            raise RuntimeError("Gemini API key not configured. Go to Settings → AI.")
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{model}:generateContent?key={api_key}"
        )
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": f"{system}\n\n{prompt}"}
                    ]
                }
            ],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 4096},
        }
        resp = requests.post(url, json=payload, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]

    def _ollama(self, prompt: str, system: str, model: str) -> str:
        base_url = self._config.get("ollama_base_url", "http://localhost:11434")
        url = f"{base_url}/api/chat"
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "options": {"temperature": 0.2},
        }
        resp = requests.post(url, json=payload, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        return data["message"]["content"]
