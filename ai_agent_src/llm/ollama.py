"""Ollama backend — local LLM via /api/generate."""
import json
import os
import re

import httpx

from .base import LLMBackend, LLMError


class OllamaBackend(LLMBackend):
    name = "ollama"

    def __init__(self):
        host = os.getenv("OLLAMA_HOST", "host.docker.internal")
        port = os.getenv("OLLAMA_PORT", "11434")
        self._url = f"http://{host}:{port}/api/generate"
        self._model = os.getenv("OLLAMA_MODEL", "qwen3:1.7b")

    @property
    def available(self) -> bool:
        return bool(self._model)

    async def analyze(self, prompt: str, timeout: int = 300) -> dict:
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                r = await client.post(
                    self._url,
                    json={
                        "model":  self._model,
                        "prompt": prompt,
                        "stream": False,
                        "format": "json",
                        "think":  False,
                    },
                )
            if r.status_code != 200:
                raise LLMError(f"Ollama HTTP {r.status_code}: {r.text[:200]}")
            raw = r.json().get("response", "")
            return _extract_json(raw, source="ollama")
        except httpx.ReadTimeout as exc:
            raise LLMError(f"Ollama timeout after {timeout}s — model '{self._model}' may need pull") from exc
        except httpx.ConnectError as exc:
            raise LLMError("Cannot reach Ollama — run: ollama serve") from exc


def _extract_json(raw: str, *, source: str) -> dict:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        match = re.search(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", raw, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError as exc:
                raise LLMError(f"{source}: extracted JSON invalid: {exc}") from exc
        raise LLMError(f"{source}: no JSON object found in response")
