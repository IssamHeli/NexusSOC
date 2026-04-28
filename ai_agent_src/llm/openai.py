"""OpenAI backend — Chat Completions with JSON response_format."""
import json
import os

import httpx

from .base import LLMBackend, LLMError


class OpenAIBackend(LLMBackend):
    name = "openai"
    _ENDPOINT = "https://api.openai.com/v1/chat/completions"

    def __init__(self):
        self._api_key = os.getenv("OPENAI_API_KEY", "").strip()
        self._model   = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        base = os.getenv("OPENAI_BASE_URL", "").strip().rstrip("/")
        self._url = base + "/chat/completions" if base else self._ENDPOINT

    @property
    def available(self) -> bool:
        return bool(self._api_key)

    async def analyze(self, prompt: str, timeout: int = 300) -> dict:
        if not self._api_key:
            raise LLMError("OPENAI_API_KEY not set")
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type":  "application/json",
        }
        payload = {
            "model":           self._model,
            "messages":        [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"},
            "temperature":     0.2,
        }
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                r = await client.post(self._url, headers=headers, json=payload)
        except httpx.ReadTimeout as exc:
            raise LLMError(f"OpenAI timeout after {timeout}s") from exc
        except httpx.ConnectError as exc:
            raise LLMError(f"Cannot reach OpenAI: {exc}") from exc

        if r.status_code != 200:
            raise LLMError(f"OpenAI HTTP {r.status_code}: {r.text[:200]}")
        data = r.json()
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"OpenAI malformed response: {exc}") from exc
        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:
            raise LLMError(f"OpenAI returned non-JSON content: {exc}") from exc
