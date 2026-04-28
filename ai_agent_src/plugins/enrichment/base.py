from abc import ABC, abstractmethod


class EnrichmentPlugin(ABC):
    name: str = ""
    required_env: list[str] = []

    @abstractmethod
    async def enrich(self, alert: dict) -> dict:
        """Return dict of extra context fields to surface in analysis prompt."""
        ...
