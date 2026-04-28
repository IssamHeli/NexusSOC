"""Anthropic backend — Messages API; instructs the model to return JSON only."""
import json
import os
import re

import httpx

from .base import LLMBackend, LLMError


class AnthropicBackend(LLMBackend):
    name = "anthropic"
    _ENDPOINT = "https://api.anthropic.com/v1/messages"
    _VERSION  = "2023-06-01"

    def __init__(self):
        self._api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
        self._model   = os.getenv("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")
        self._max_tokens = int(os.getenv("ANTHROPIC_MAX_TOKENS", "2048"))

    @property
    def available(self) -> bool:
        return bool(self._api_key)

    async def analyze(self, prompt: str, timeout: int = 300) -> dict:
        if not self._api_key:
            raise LLMError("ANTHROPIC_API_KEY not set")
        headers = {
            "x-api-key":         self._api_key,
            "anthropic-version": self._VERSION,
            "Content-Type":      "application/json",
        }
        payload = {
            "model":      self._model,
            "max_tokens": self._max_tokens,
            "system":     "Respond with a single JSON object only — no prose, no markdown fences.",
            "messages":   [{"role": "user", "content": prompt}],
        }
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                r = await client.post(self._ENDPOINT, headers=headers, json=payload)
        except httpx.ReadTimeout as exc:
            raise LLMError(f"Anthropic timeout after {timeout}s") from exc
        except httpx.ConnectError as exc:
            raise LLMError(f"Cannot reach Anthropic: {exc}") from exc

        if r.status_code != 200:
            raise LLMError(f"Anthropic HTTP {r.status_code}: {r.text[:200]}")
        data = r.json()
        try:
            blocks = data["content"]
            text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        except (KeyError, TypeError) as exc:
            raise LLMError(f"Anthropic malformed response: {exc}") from exc

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            match = re.search(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group())
                except json.JSONDecodeError as exc:
                    raise LLMError(f"Anthropic extracted JSON invalid: {exc}") from exc
            raise LLMError("Anthropic returned no JSON object")
