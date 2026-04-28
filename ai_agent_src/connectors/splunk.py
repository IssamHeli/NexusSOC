import uuid
from typing import Any
from .base import SIEMConnector, _infer_attack_type


class SplunkConnector(SIEMConnector):
    """Normalizes Splunk saved-search webhook alerts to SecurityAlert format."""

    @property
    def source_name(self) -> str:
        return "splunk"

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        result      = raw.get("result", raw)
        search_name = raw.get("search_name") or result.get("search_name", "Splunk alert")
        sid         = raw.get("sid") or str(uuid.uuid4())

        src_ip   = result.get("src") or result.get("src_ip")
        dst_ip   = result.get("dest") or result.get("dest_ip")
        dst_port = result.get("dest_port") or result.get("port")
        proto    = result.get("protocol") or result.get("transport")

        signature = result.get("signature") or result.get("description") or search_name
        severity  = (result.get("severity") or result.get("urgency") or "medium").lower()
        if severity not in ("low", "medium", "high", "critical"):
            severity = "medium"

        count = result.get("count") or result.get("event_count")

        indicators = [ip for ip in [src_ip] if ip]

        network = None
        if src_ip or dst_ip:
            network = {
                "source_ip":      src_ip,
                "destination_ip": dst_ip,
                "protocol":       proto,
                "port":           int(dst_port) if dst_port and str(dst_port).isdigit() else None,
            }

        desc_parts = [f"Splunk saved search '{search_name}' triggered.", signature]
        if count:
            desc_parts.append(f"Event count: {count}.")

        return {
            "sourceRef":   f"SPLUNK-{str(sid)[:50]}",
            "title":       search_name,
            "description": " ".join(desc_parts),
            "source":      "Splunk DLP",
            "severity":    severity,
            "timestamp":   raw.get("trigger_time") or result.get("_time"),
            "hostname":    result.get("host") or result.get("dest"),
            "user":        result.get("user") or result.get("src_user"),
            "indicators":  indicators or None,
            "network":     network,
            "attack_type": _infer_attack_type([search_name, signature]),
            "event_count": int(count) if count and str(count).isdigit() else None,
        }
