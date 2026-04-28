import uuid
from datetime import datetime, timezone
from typing import Any
from .base import SIEMConnector, _magnitude_to_severity, _infer_attack_type


class QRadarConnector(SIEMConnector):
    """Normalizes QRadar offense payloads to SecurityAlert format."""

    @property
    def source_name(self) -> str:
        return "qradar"

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        offense_id  = raw.get("id") or str(uuid.uuid4())
        description = raw.get("description") or raw.get("offense_name", "QRadar offense")
        magnitude   = int(raw.get("magnitude", raw.get("severity", 5)))
        categories  = raw.get("categories") or []
        src_ips     = raw.get("source_address_ids") or raw.get("source_ips") or []
        event_count = raw.get("event_count")

        # start_time is epoch milliseconds
        timestamp = None
        start_ms  = raw.get("start_time")
        if start_ms:
            try:
                timestamp = datetime.fromtimestamp(
                    int(start_ms) / 1000, tz=timezone.utc
                ).isoformat()
            except (ValueError, OSError):
                pass

        src_ip     = src_ips[0] if src_ips else None
        indicators = [ip for ip in src_ips[:5] if ip]

        network = None
        if src_ip:
            network = {"source_ip": src_ip, "destination_ip": None, "protocol": None, "port": None}

        desc_full = (
            f"QRadar Offense #{offense_id}: {description}."
            + (f" Categories: {', '.join(str(c) for c in categories)}." if categories else "")
            + (f" Event count: {event_count}." if event_count else "")
        )

        return {
            "sourceRef":   f"QRADAR-{offense_id}",
            "title":       description,
            "description": desc_full,
            "source":      "SIEM",
            "severity":    _magnitude_to_severity(magnitude),
            "timestamp":   timestamp,
            "indicators":  indicators or None,
            "network":     network,
            "attack_type": _infer_attack_type([str(c) for c in categories] + [description]),
            "event_count": int(event_count) if event_count else None,
        }
