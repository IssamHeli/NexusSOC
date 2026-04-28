import os
import logging

import httpx

from .base import NotificationPlugin

logger = logging.getLogger(__name__)


class TeamsPlugin(NotificationPlugin):
    name = "teams"
    required_env = ["TEAMS_WEBHOOK"]

    def __init__(self):
        self._url = os.getenv("TEAMS_WEBHOOK", "").strip()

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
        card = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "E74C3C" if decision.lower() == "true positive" else "2ECC71",
            "summary": f"[{decision}] {case_id}",
            "sections": [{
                "activityTitle": f"**[{decision.upper()}]** {title}",
                "activitySubtitle": f"Case `{case_id}` — Confidence {conf_pct}%",
                "text": explanation[:500],
            }],
        }
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(self._url, json=card)
                return r.status_code < 300
        except Exception as e:
            logger.error(f"Teams notification failed: {e}")
            return False
