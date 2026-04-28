"""LLMRouter — picks primary backend, falls through fallback chain on LLMError."""
import logging
import os

from .anthropic import AnthropicBackend
from .base import LLMBackend, LLMError
from .ollama import OllamaBackend
from .openai import OpenAIBackend

logger = logging.getLogger(__name__)

_REGISTRY: dict[str, type[LLMBackend]] = {
    "ollama":    OllamaBackend,
    "openai":    OpenAIBackend,
    "anthropic": AnthropicBackend,
}


class LLMRouter:
    """Routes analyze() to a primary backend; on LLMError, walks fallback chain."""

    def __init__(self) -> None:
        primary = os.getenv("LLM_BACKEND", "ollama").lower().strip()
        chain   = os.getenv("LLM_FALLBACK_CHAIN", "").strip()

        order = [primary] + [n.strip().lower() for n in chain.split(",") if n.strip()]
        seen: set[str] = set()
        self._chain: list[LLMBackend] = []
        for name in order:
            if name in seen:
                continue
            seen.add(name)
            cls = _REGISTRY.get(name)
            if not cls:
                logger.warning("LLMRouter: unknown backend '%s' — skipped", name)
                continue
            try:
                self._chain.append(cls())
            except Exception as exc:
                logger.warning("LLMRouter: backend '%s' init failed: %s", name, exc)

        if not self._chain:
            logger.warning("LLMRouter: no backend resolved — defaulting to OllamaBackend")
            self._chain = [OllamaBackend()]

        logger.info("LLMRouter chain: %s", " -> ".join(b.name for b in self._chain))

    @property
    def primary(self) -> str:
        return self._chain[0].name

    @property
    def fallback_chain(self) -> list[str]:
        return [b.name for b in self._chain[1:]]

    def status(self) -> dict:
        return {
            "primary":        self.primary,
            "fallback_chain": self.fallback_chain,
            "available":      {b.name: b.available for b in self._chain},
        }

    async def analyze(self, prompt: str, timeout: int = 300) -> dict:
        last_err: LLMError | None = None
        for backend in self._chain:
            if not backend.available:
                logger.info("LLMRouter: skipping '%s' — not configured", backend.name)
                continue
            try:
                return await backend.analyze(prompt, timeout=timeout)
            except LLMError as exc:
                logger.warning("LLMRouter: '%s' failed (%s) — trying next", backend.name, exc)
                last_err = exc

        if last_err:
            raise last_err
        raise LLMError("No LLM backend available — set LLM_BACKEND and required API key")
