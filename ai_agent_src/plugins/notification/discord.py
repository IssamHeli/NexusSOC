import os
import logging
from datetime import datetime, timezone

import httpx

from .base import NotificationPlugin

logger = logging.getLogger(__name__)


class DiscordPlugin(NotificationPlugin):
    name = "discord"
    required_env = ["DISCORD_WEBHOOK"]

    def __init__(self):
        self._url = os.getenv("DISCORD_WEBHOOK", "").strip()

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

        is_tp = decision.lower() == "true positive"
        embed_title = "🚨 THREAT CONFIRMED — TRUE POSITIVE" if is_tp else "✅ FALSE POSITIVE — NO ACTION"
        embed_color = 0xE74C3C if is_tp else 0x2ECC71

        conf_pct = round(confidence * 100, 1)
        conf_bar = "█" * int(conf_pct // 10) + "░" * (10 - int(conf_pct // 10))

        severity = getattr(alert, "severity",        "—") if alert else "—"
        attack   = getattr(alert, "attack_type",      "—") if alert else "—"
        kill_ch  = getattr(alert, "kill_chain_phase", "—") if alert else "—"
        hostname = getattr(alert, "hostname",         "")  if alert else ""
        user     = getattr(alert, "user",             "")  if alert else ""
        mitre    = getattr(alert, "mitre_techniques", [])  if alert else []
        net      = getattr(alert, "network",          None) if alert else None
        src_ip   = getattr(net, "source_ip", "") if net else ""

        fields = [
            {"name": "📋 Case",       "value": f"`{case_id}`",                  "inline": True},
            {"name": "⚖️ Decision",   "value": f"**{decision}**",               "inline": True},
            {"name": "📊 Confidence", "value": f"`{conf_bar}` **{conf_pct}%**", "inline": True},
        ]

        ctx = []
        if severity and severity != "—": ctx.append(f"**Severity:** `{str(severity).upper()}`")
        if attack   and attack   != "—": ctx.append(f"**Type:** `{attack}`")
        if kill_ch  and kill_ch  != "—": ctx.append(f"**Kill chain:** `{kill_ch}`")
        if ctx:
            fields.append({"name": "🎯 Threat Context", "value": "  ·  ".join(ctx)})

        ids = []
        if hostname: ids.append(f"**Host:** `{hostname}`")
        if user:     ids.append(f"**User:** `{user}`")
        if src_ip:   ids.append(f"**Src IP:** `{src_ip}`")
        if ids:
            fields.append({"name": "🖥️ Asset / Identity", "value": "  ·  ".join(ids)})

        if mitre:
            fields.append({"name": "🛡️ MITRE ATT&CK", "value": "  ".join(f"`{t}`" for t in mitre[:8])})

        fields.append({"name": "🤖 AI Analysis", "value": explanation[:1000]})

        if recommended_action:
            fields.append({"name": "⚡ Recommended Action", "value": f"```{recommended_action[:480]}```"})

        embed = {
            "title":       embed_title,
            "description": f"**{title[:250]}**",
            "color":       embed_color,
            "fields":      fields,
            "footer":      {"text": f"NexusSOC AI Agent  ·  Case {case_id}"},
            "timestamp":   datetime.now(timezone.utc).isoformat(),
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(self._url, json={"embeds": [embed]})
                return r.status_code < 300
        except Exception as e:
            logger.error(f"Discord notification failed: {e}")
            return False
