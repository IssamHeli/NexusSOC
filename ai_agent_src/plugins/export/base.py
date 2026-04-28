from abc import ABC, abstractmethod


class ExportPlugin(ABC):
    name: str = ""
    required_env: list[str] = []

    @abstractmethod
    async def export(self, pool) -> dict:
        """Export data. Returns {content: str, media_type: str, filename: str}."""
        ...
