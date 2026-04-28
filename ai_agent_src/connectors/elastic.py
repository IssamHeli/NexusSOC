import uuid
from typing import Any
from .base import SIEMConnector, _infer_attack_type


class ElasticConnector(SIEMConnector):
    """Normalizes Elastic Security (SIEM) alert hits to SecurityAlert format."""

    @property
    def source_name(self) -> str:
        return "elastic"

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        # Accepts both raw ES hit {_id, _source} and unwrapped _source dict
        src    = raw.get("_source", raw)
        hit_id = raw.get("_id") or str(uuid.uuid4())

        rule   = src.get("rule", {})
        host   = src.get("host", {})
        source = src.get("source", {})
        dest   = src.get("destination", {})
        net    = src.get("network", {})
        threat = src.get("threat", {})

        rule_name = (
            rule.get("name")
            or src.get("signal", {}).get("rule", {}).get("name", "Elastic SIEM alert")
        )
        severity = (rule.get("severity") or src.get("kibana.alert.severity", "medium")).lower()
        reason   = src.get("kibana.alert.reason") or src.get("message") or rule_name

        host_ips = host.get("ip", [])
        src_ip   = source.get("ip")
        dst_ip   = dest.get("ip")
        dst_port = dest.get("port")
        protocol = net.get("protocol") or net.get("transport")

        indicators = list({ip for ip in ([src_ip] + host_ips) if ip})

        network = None
        if src_ip or dst_ip:
            network = {
                "source_ip":      src_ip,
                "destination_ip": dst_ip,
                "protocol":       protocol,
                "port":           int(dst_port) if dst_port and str(dst_port).isdigit() else None,
            }

        techniques = [t.get("id") for t in threat.get("technique", []) if t.get("id")] or None

        return {
            "sourceRef":        f"ELASTIC-{hit_id}",
            "title":            rule_name,
            "description":      reason,
            "source":           "SIEM",
            "severity":         severity if severity in ("low", "medium", "high", "critical") else "medium",
            "timestamp":        src.get("@timestamp"),
            "hostname":         host.get("name"),
            "user":             src.get("user", {}).get("name"),
            "indicators":       indicators or None,
            "network":          network,
            "attack_type":      _infer_attack_type([rule_name, reason]),
            "mitre_techniques": techniques,
        }
