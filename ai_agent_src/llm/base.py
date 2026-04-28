"""LLM backend abstraction — every provider returns parsed JSON dict."""
from abc import ABC, abstractmethod


class LLMError(Exception):
    """Raised when a backend cannot complete a request (timeout, network, parse, auth)."""


class LLMBackend(ABC):
    """All backends: take a prompt, return a JSON dict."""

    name: str = "abstract"

    @abstractmethod
    async def analyze(self, prompt: str, timeout: int = 300) -> dict:
        """Send prompt; return parsed JSON dict. Raise LLMError on failure."""
        ...

    @property
    @abstractmethod
    def available(self) -> bool:
        """True when required env/config is present (does not network-probe)."""
        ...
