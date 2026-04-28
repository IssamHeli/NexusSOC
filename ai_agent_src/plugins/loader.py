import importlib
import logging
import os

logger = logging.getLogger(__name__)

_REGISTRY = [
    # (env_var, module_path, class_name, category, default_enabled)
    ("PLUGIN_DISCORD_ENABLED",      "plugins.notification.discord",  "DiscordPlugin",    "notification", "true"),
    ("PLUGIN_SLACK_ENABLED",        "plugins.notification.slack",    "SlackPlugin",      "notification", "false"),
    ("PLUGIN_TEAMS_ENABLED",        "plugins.notification.teams",    "TeamsPlugin",      "notification", "false"),
    ("PLUGIN_VT_ENABLED",           "plugins.enrichment.virustotal", "VirusTotalPlugin", "enrichment",   "false"),
    ("PLUGIN_ABUSEIPDB_ENABLED",    "plugins.enrichment.abuseipdb",  "AbuseIPDBPlugin",  "enrichment",   "false"),
    ("PLUGIN_MITRE_EXPORT_ENABLED", "plugins.export.mitre_nav",      "MitreNavPlugin",   "export",       "true"),
    ("PLUGIN_STIX2_ENABLED",        "plugins.export.stix2",          "Stix2Plugin",      "export",       "false"),
]


class PluginLoader:
    def __init__(self):
        self.enrichment:   list = []
        self.notification: list = []
        self.export:       list = []
        self._status:      list[dict] = []

    def load_all(self) -> None:
        for env_var, module_path, class_name, category, default in _REGISTRY:
            enabled = os.getenv(env_var, default).lower() == "true"
            if not enabled:
                self._status.append({"name": class_name, "category": category, "loaded": False, "reason": "disabled"})
                continue
            try:
                mod      = importlib.import_module(module_path)
                cls      = getattr(mod, class_name)
                instance = cls()
                missing  = [v for v in instance.required_env if not os.getenv(v)]
                if missing:
                    logger.warning(f"Plugin {class_name} skipped — missing env vars: {missing}")
                    self._status.append({"name": instance.name, "category": category, "loaded": False, "reason": f"missing env: {missing}"})
                    continue
                getattr(self, category).append(instance)
                logger.info(f"Plugin loaded: {instance.name} [{category}]")
                self._status.append({"name": instance.name, "category": category, "loaded": True, "reason": "ok"})
            except Exception as e:
                logger.error(f"Plugin {class_name} failed to load: {e}")
                self._status.append({"name": class_name, "category": category, "loaded": False, "reason": str(e)})

    def status(self) -> list[dict]:
        return self._status

    def get_export(self, name: str):
        return next((p for p in self.export if p.name == name), None)

    async def notify_all(
        self,
        case_id: str,
        title: str,
        decision: str,
        confidence: float,
        explanation: str,
        recommended_action: str,
        alert=None,
    ) -> None:
        for plugin in self.notification:
            try:
                await plugin.notify(case_id, title, decision, confidence, explanation, recommended_action, alert)
            except Exception as e:
                logger.warning(f"Notification plugin {plugin.name} error: {e}")
