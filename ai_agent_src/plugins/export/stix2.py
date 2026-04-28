import json
import logging
import re
import uuid
from datetime import datetime, timezone

from .base import ExportPlugin

logger = logging.getLogger(__name__)


_NEXUSSOC_IDENTITY_ID = "identity--6f5d1e9f-7a4b-4c0d-9b2a-1e3c5f7a9b00"

_IPV4_RE        = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
_HASH_MD5_RE    = re.compile(r"^[a-fA-F0-9]{32}$")
_HASH_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _stix_id(prefix: str) -> str:
    return f"{prefix}--{uuid.uuid4()}"


def _identity_obj() -> dict:
    now = _now_iso()
    return {
        "type":           "identity",
        "spec_version":   "2.1",
        "id":             _NEXUSSOC_IDENTITY_ID,
        "created":        now,
        "modified":       now,
        "name":           "NexusSOC AI Agent",
        "identity_class": "system",
        "description":    "Local AI-powered SOC analyst — autonomous alert triage and skill learning",
    }


def _classify_indicator(value: str) -> tuple[str, str] | None:
    """Return (STIX pattern, human description) for a known IOC value."""
    v = value.strip()
    if not v:
        return None
    if _IPV4_RE.match(v):
        return f"[ipv4-addr:value = '{v}']", "IPv4 address"
    if _HASH_SHA256_RE.match(v):
        return f"[file:hashes.'SHA-256' = '{v}']", "SHA-256 file hash"
    if _HASH_MD5_RE.match(v):
        return f"[file:hashes.MD5 = '{v}']", "MD5 file hash"
    if v.startswith("CVE-"):
        return f"[vulnerability:name = '{v}']", "CVE reference"
    if "." in v and "/" not in v:
        return f"[domain-name:value = '{v}']", "Domain name"
    return None


def _indicator_obj(pattern: str, description: str, created: str, kill_chain: str | None) -> dict:
    obj = {
        "type":            "indicator",
        "spec_version":    "2.1",
        "id":              _stix_id("indicator"),
        "created":         created,
        "modified":        created,
        "created_by_ref":  _NEXUSSOC_IDENTITY_ID,
        "name":            description,
        "pattern":         pattern,
        "pattern_type":    "stix",
        "valid_from":      created,
        "indicator_types": ["malicious-activity"],
    }
    if kill_chain:
        obj["kill_chain_phases"] = [{
            "kill_chain_name": "lockheed-martin-cyber-kill-chain",
            "phase_name":      kill_chain,
        }]
    return obj


def _attack_pattern_obj(technique_id: str, created: str) -> dict:
    return {
        "type":               "attack-pattern",
        "spec_version":       "2.1",
        "id":                 _stix_id("attack-pattern"),
        "created":             created,
        "modified":            created,
        "created_by_ref":      _NEXUSSOC_IDENTITY_ID,
        "name":                f"MITRE ATT&CK {technique_id}",
        "external_references": [{
            "source_name": "mitre-attack",
            "external_id": technique_id,
            "url":         f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
        }],
    }


def _report_obj(case_id: str, alert: dict, decision: str, confidence: float,
                summary: str, action: str, created: str, object_refs: list[str]) -> dict:
    title = alert.get("title", "Untitled")
    return {
        "type":           "report",
        "spec_version":   "2.1",
        "id":             _stix_id("report"),
        "created":        created,
        "modified":       created,
        "created_by_ref": _NEXUSSOC_IDENTITY_ID,
        "name":           f"NexusSOC Case {case_id} — {title}",
        "description":    (
            f"AI Decision: {decision} (confidence {confidence:.0%})\n\n"
            f"Analysis: {summary}\n\nRecommended Action: {action}"
        ),
        "report_types":   ["threat-report"],
        "published":      created,
        "object_refs":    object_refs or [_NEXUSSOC_IDENTITY_ID],
        "labels":         [decision.lower().replace(" ", "-"), f"confidence-{int(confidence*100)}"],
    }


def _relationship(source: str, target: str, rel_type: str, created: str) -> dict:
    return {
        "type":              "relationship",
        "spec_version":      "2.1",
        "id":                _stix_id("relationship"),
        "created":           created,
        "modified":          created,
        "created_by_ref":    _NEXUSSOC_IDENTITY_ID,
        "relationship_type": rel_type,
        "source_ref":        source,
        "target_ref":        target,
    }


class Stix2Plugin(ExportPlugin):
    name = "stix2"
    required_env: list[str] = []

    async def export(self, pool) -> dict:
        """Bulk export of recent high-confidence True Positive cases as a STIX 2.1 bundle."""
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT case_id, raw_alert, ai_decision, confidence, analysis_summary,
                       recommended_action, timestamp
                FROM ai_analysis
                WHERE ai_decision = 'True Positive' AND confidence >= 0.85
                ORDER BY timestamp DESC
                LIMIT 100
                """
            )

        objects: list[dict] = [_identity_obj()]
        for row in rows:
            objects.extend(self._build_case_objects(dict(row)))

        bundle = {
            "type":         "bundle",
            "id":           _stix_id("bundle"),
            "spec_version": "2.1",
            "objects":      objects,
        }
        return {
            "content":    json.dumps(bundle, indent=2),
            "media_type": "application/json",
            "filename":   f"nexussoc-stix2-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json",
        }

    async def export_case(self, pool, case_id: str) -> dict | None:
        """Export a single case as a STIX 2.1 bundle. Returns None if the case is missing."""
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT case_id, raw_alert, ai_decision, confidence, analysis_summary,
                       recommended_action, timestamp
                FROM ai_analysis
                WHERE case_id = $1
                ORDER BY timestamp DESC
                LIMIT 1
                """,
                case_id,
            )
        if not row:
            return None

        objects = [_identity_obj()] + self._build_case_objects(dict(row))
        bundle = {
            "type":         "bundle",
            "id":           _stix_id("bundle"),
            "spec_version": "2.1",
            "objects":      objects,
        }
        return {
            "content":    json.dumps(bundle, indent=2),
            "media_type": "application/json",
            "filename":   f"nexussoc-{case_id}-stix2.json",
        }

    def _build_case_objects(self, row: dict) -> list[dict]:
        """Convert one ai_analysis row into a list of STIX SDOs."""
        case_id = row["case_id"]
        raw     = row["raw_alert"]
        alert   = json.loads(raw) if isinstance(raw, str) else (raw or {})
        ts      = row["timestamp"]
        created = ts.strftime("%Y-%m-%dT%H:%M:%S.000Z") if hasattr(ts, "strftime") else _now_iso()

        objects: list[dict] = []
        ref_ids:  list[str] = []
        kill_chain = alert.get("kill_chain_phase")

        def _push_indicator(value: str, label_extra: str = "") -> None:
            cls = _classify_indicator(str(value))
            if not cls:
                return
            pattern, desc = cls
            full_desc = f"{desc}{label_extra}"
            ind = _indicator_obj(pattern, full_desc, created, kill_chain)
            objects.append(ind)
            ref_ids.append(ind["id"])

        for raw_value in alert.get("indicators", []) or []:
            _push_indicator(str(raw_value))

        net = alert.get("network") or {}
        for field in ("source_ip", "destination_ip"):
            if net.get(field):
                _push_indicator(net[field], f" ({field})")

        fa = alert.get("file_analysis") or {}
        for hash_field in ("file_hash_sha256", "file_hash_md5"):
            if fa.get(hash_field):
                _push_indicator(fa[hash_field])

        attack_ids: list[str] = []
        for tech in alert.get("mitre_techniques") or []:
            ap = _attack_pattern_obj(str(tech), created)
            objects.append(ap)
            attack_ids.append(ap["id"])
            ref_ids.append(ap["id"])

        for ind in [o for o in objects if o.get("type") == "indicator"]:
            for ap_id in attack_ids:
                rel = _relationship(ind["id"], ap_id, "indicates", created)
                objects.append(rel)
                ref_ids.append(rel["id"])

        report = _report_obj(
            case_id, alert, row["ai_decision"], float(row["confidence"]),
            row["analysis_summary"] or "", row["recommended_action"] or "",
            created, ref_ids,
        )
        objects.append(report)

        return objects
