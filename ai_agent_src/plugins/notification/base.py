from abc import ABC, abstractmethod


class NotificationPlugin(ABC):
    name: str = ""
    required_env: list[str] = []

    @abstractmethod
    async def notify(
        self,
        case_id: str,
        title: str,
        decision: str,
        confidence: float,
        explanation: str,
        recommended_action: str,
        alert=None,
    ) -> bool:
        """Send notification. Returns True if delivered successfully."""
        ...
