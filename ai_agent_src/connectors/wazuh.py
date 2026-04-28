import uuid
from typing import Any
from .base import SIEMConnector, _wazuh_level_to_severity, _infer_attack_type


class WazuhConnector(SIEMConnector):
    """Normalizes Wazuh HIDS/SIEM alerts to SecurityAlert format."""

    @property
    def source_name(self) -> str:
        return "wazuh"

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        rule   = raw.get("rule", {})
        agent  = raw.get("agent", {})
        data   = raw.get("data", {})

        level       = int(rule.get("level", 5))
        description = rule.get("description", "Wazuh alert")
        groups      = rule.get("groups", [])

        src_ip = data.get("srcip") or data.get("src_ip")
        dst_ip = data.get("dstip") or data.get("dst_ip") or agent.get("ip")
        proto  = data.get("protocol")
        port   = data.get("dstport") or data.get("dst_port")

        indicators = [ip for ip in [src_ip, agent.get("ip")] if ip]

        network = None
        if src_ip or dst_ip:
            network = {
                "source_ip":      src_ip,
                "destination_ip": dst_ip,
                "protocol":       proto,
                "port":           int(port) if port and str(port).isdigit() else None,
            }

        alert_id = raw.get("id") or str(uuid.uuid4())

        return {
            "sourceRef":        f"WAZUH-{alert_id}",
            "title":            description,
            "description":      (
                f"Wazuh rule {rule.get('id', '?')} (level {level}) on agent "
                f"'{agent.get('name', 'unknown')}'. {description}"
            ),
            "source":           "SIEM",
            "severity":         _wazuh_level_to_severity(level),
            "timestamp":        raw.get("timestamp"),
            "hostname":         agent.get("name"),
            "indicators":       indicators or None,
            "network":          network,
            "attack_type":      _infer_attack_type(groups + [description]),
            "mitre_techniques": rule.get("mitre", {}).get("id") or None,
        }
