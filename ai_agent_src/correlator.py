import logging
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

CORRELATION_WINDOW_HOURS = 24


def _make_incident_id(seed: str) -> str:
    h = hashlib.sha1(seed.encode()).hexdigest()[:6].upper()
    return f"INC-{h}"


def _collect_indicators(alert) -> dict:
    source_ip = (alert.network.source_ip if alert.network else None) or ""
    file_hash = ""
    if alert.file_analysis:
        file_hash = alert.file_analysis.file_hash_sha256 or alert.file_analysis.file_hash_md5 or ""
    return {
        "source_ip": source_ip,
        "hostname":  getattr(alert, "hostname", "") or "",
        "user":      getattr(alert, "user", "") or "",
        "file_hash": file_hash,
    }


async def correlate_alert(
    pool,
    alert,
    result: dict,
    embedding: Optional[list] = None,
) -> Optional[dict]:
    """
    Correlate alert against open incidents within CORRELATION_WINDOW_HOURS.
    Match priority: explicit correlated_cases > shared IP/hostname/user.
    - Match found: add case to incident, update kill chain + indicators.
    - No match + True Positive: open new incident.
    - No match + False Positive: return None.
    """
    decision     = result.get("decision", "")
    indicators   = _collect_indicators(alert)
    case_id      = alert.sourceRef
    now          = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=CORRELATION_WINDOW_HOURS)

    kill_chain = getattr(alert, "kill_chain_phase", None) or ""
    mitre      = list(alert.mitre_techniques or [])
    attack     = getattr(alert, "attack_type", None) or ""
    severity   = getattr(alert, "severity", "medium") or "medium"

    async with pool.acquire() as conn:
        existing = None
        explicit_ids = list(alert.correlated_cases or [])

        if explicit_ids:
            existing = await conn.fetchrow("""
                SELECT * FROM soc_incidents
                WHERE case_ids && $1::text[]
                  AND updated_at >= $2
                  AND status != 'closed'
                ORDER BY updated_at DESC LIMIT 1
            """, explicit_ids, window_start)

        if not existing and any([indicators["source_ip"], indicators["hostname"], indicators["user"]]):
            existing = await conn.fetchrow("""
                SELECT * FROM soc_incidents
                WHERE updated_at >= $1
                  AND status != 'closed'
                  AND (
                    ($2 != '' AND $2 = ANY(source_ips))
                    OR ($3 != '' AND $3 = ANY(hostnames))
                    OR ($4 != '' AND $4 = ANY(users))
                  )
                ORDER BY updated_at DESC LIMIT 1
            """, window_start,
                indicators["source_ip"],
                indicators["hostname"],
                indicators["user"])

        if existing:
            inc_id = existing["incident_id"]

            new_cases = list(existing["case_ids"] or [])
            if case_id not in new_cases:
                new_cases.append(case_id)

            new_phases = list(existing["kill_chain_phases"] or [])
            if kill_chain and kill_chain not in new_phases:
                new_phases.append(kill_chain)

            new_ips = list(existing["source_ips"] or [])
            if indicators["source_ip"] and indicators["source_ip"] not in new_ips:
                new_ips.append(indicators["source_ip"])

            new_hosts = list(existing["hostnames"] or [])
            if indicators["hostname"] and indicators["hostname"] not in new_hosts:
                new_hosts.append(indicators["hostname"])

            new_users = list(existing["users"] or [])
            if indicators["user"] and indicators["user"] not in new_users:
                new_users.append(indicators["user"])

            new_attacks = list(existing["attack_types"] or [])
            if attack and attack not in new_attacks:
                new_attacks.append(attack)

            new_mitre = list(existing["mitre_techniques"] or [])
            for t in mitre:
                if t not in new_mitre:
                    new_mitre.append(t)

            sev_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
            new_sev  = severity if sev_rank.get(severity, 0) > sev_rank.get(existing["severity"], 0) else existing["severity"]

            await conn.execute("""
                UPDATE soc_incidents SET
                    case_ids          = $1,
                    kill_chain_phases = $2,
                    source_ips        = $3,
                    hostnames         = $4,
                    users             = $5,
                    attack_types      = $6,
                    mitre_techniques  = $7,
                    severity          = $8,
                    case_count        = case_count + 1,
                    updated_at        = NOW()
                WHERE incident_id = $9
            """, new_cases, new_phases, new_ips, new_hosts, new_users,
                new_attacks, new_mitre, new_sev, inc_id)

            logger.info(f"Correlated {case_id} → incident {inc_id} ({len(new_cases)} cases)")
            return {
                "incident_id":       inc_id,
                "action":            "updated",
                "case_count":        len(new_cases),
                "kill_chain_phases": new_phases,
                "severity":          new_sev,
            }

        if decision != "True Positive":
            return None

        inc_id = _make_incident_id(f"{case_id}{now.isoformat()}")
        title  = f"[{attack or 'Unknown'}] {alert.title[:80]}"

        await conn.execute("""
            INSERT INTO soc_incidents (
                incident_id, title, status, severity,
                case_ids, kill_chain_phases,
                source_ips, hostnames, users,
                attack_types, mitre_techniques, case_count
            ) VALUES ($1,$2,'open',$3,$4,$5,$6,$7,$8,$9,$10,1)
        """,
            inc_id, title, severity,
            [case_id],
            [kill_chain] if kill_chain else [],
            [indicators["source_ip"]] if indicators["source_ip"] else [],
            [indicators["hostname"]]  if indicators["hostname"]  else [],
            [indicators["user"]]      if indicators["user"]      else [],
            [attack] if attack else [],
            mitre,
        )

        logger.info(f"New incident {inc_id} opened for {case_id}")
        return {
            "incident_id":       inc_id,
            "action":            "created",
            "case_count":        1,
            "kill_chain_phases": [kill_chain] if kill_chain else [],
            "severity":          severity,
        }
