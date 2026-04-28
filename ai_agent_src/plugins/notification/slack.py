import os
import logging

import httpx

from .base import NotificationPlugin

logger = logging.getLogger(__name__)


class SlackPlugin(NotificationPlugin):
    name = "slack"
    required_env = ["SLACK_WEBHOOK"]

    def __init__(self):
        self._url = os.getenv("SLACK_WEBHOOK", "").strip()

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
        if not self._url:
            return False
        conf_pct = round(confidence * 100, 1)
        text = (
            f"*[{decision.upper()}]* `{case_id}` — {title}\n"
            f"Confidence: *{conf_pct}%* | {explanation[:300]}"
        )
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(self._url, json={"text": text})
                return r.status_code < 300
        except Exception as e:
            logger.error(f"Slack notification failed: {e}")
            return False
