"""
Seed default SOC playbooks via the /playbooks API.

Usage:
    python seed_playbooks.py                          # localhost:8000
    python seed_playbooks.py http://soc-agent:8000    # remote
"""
import asyncio
import sys
import httpx

BASE_URL = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000").rstrip("/")

PLAYBOOKS = [
    # ── Brute Force ─────────────────────────────────────────────────────────────
    {
        "name": "Brute Force — Block & Notify",
        "description": (
            "Triggered on confirmed brute-force attacks. "
            "Logs the event, fires a Discord alert, and calls the firewall webhook to block the source IP."
        ),
        "trigger_decision": "True Positive",
        "trigger_min_confidence": 0.80,
        "trigger_attack_types": ["brute_force"],
        "enabled": True,
        "actions": [
            {
                "type": "log",
                "message": "[BRUTE-FORCE] Case {case_id} — source IP {source_ip} on host {hostname}",
            },
            {
                "type": "discord",
                "message": (
                    "🔐 **BRUTE FORCE DETECTED** | Case `{case_id}`\n"
                    "Host: `{hostname}` | Source IP: `{source_ip}`\n"
                    "Confidence: **{confidence}** | Action: block source IP & reset credentials"
                ),
            },
            {
                "type": "webhook",
                "url": "http://firewall-api/block-ip",
                "method": "POST",
                "payload": {
                    "source_ip": "{source_ip}",
                    "reason": "brute_force",
                    "case_id": "{case_id}",
                    "duration_hours": 24,
                },
            },
            {
                "type": "webhook",
                "url": "http://soar/tickets",
                "method": "POST",
                "payload": {
                    "title": "Brute Force — {case_id}",
                    "priority": "high",
                    "assignee": "soc-tier1",
                    "tags": ["brute_force", "credential_attack"],
                    "case_id": "{case_id}",
                },
            },
        ],
    },

    # ── Data Exfiltration ────────────────────────────────────────────────────────
    {
        "name": "Data Exfiltration — Isolate & Escalate",
        "description": (
            "P0 response for confirmed data exfiltration. "
            "Isolates the endpoint, pages the SOC lead via Discord, and opens a P1 incident ticket."
        ),
        "trigger_decision": "True Positive",
        "trigger_min_confidence": 0.82,
        "trigger_attack_types": ["data_exfiltration"],
        "enabled": True,
        "actions": [
            {
                "type": "log",
                "message": "[EXFIL] P0 — Case {case_id} host {hostname} decision={decision} conf={confidence}",
            },
            {
                "type": "discord",
                "message": (
                    "🚨 **DATA EXFILTRATION — P0** | Case `{case_id}`\n"
                    "Host: `{hostname}` | IP: `{source_ip}`\n"
                    "Confidence: **{confidence}**\n"
                    "→ Endpoint isolated. Notify DPO if PII involved. Open P1 incident."
                ),
            },
            {
                "type": "webhook",
                "url": "http://edr-api/isolate",
                "method": "POST",
                "payload": {
                    "hostname": "{hostname}",
                    "reason": "data_exfiltration",
                    "case_id": "{case_id}",
                },
            },
            {
                "type": "webhook",
                "url": "http://soar/tickets",
                "method": "POST",
                "payload": {
                    "title": "DATA EXFILTRATION P1 — {case_id}",
                    "priority": "critical",
                    "assignee": "soc-lead",
                    "tags": ["data_exfiltration", "p1", "dlp"],
                    "case_id": "{case_id}",
                },
            },
        ],
    },

    # ── Malware ──────────────────────────────────────────────────────────────────
    {
        "name": "Malware — Quarantine Endpoint",
        "description": (
            "Isolates the infected host via EDR, notifies the SOC channel, "
            "and triggers an AV full-scan on the affected machine."
        ),
        "trigger_decision": "True Positive",
        "trigger_min_confidence": 0.80,
        "trigger_attack_types": ["malware"],
        "enabled": True,
        "actions": [
            {
                "type": "log",
                "message": "[MALWARE] Case {case_id} — host {hostname} quarantined. attack={attack_type}",
            },
            {
                "type": "discord",
                "message": (
                    "🦠 **MALWARE DETECTED** | Case `{case_id}`\n"
                    "Host: `{hostname}` | Confidence: **{confidence}**\n"
                    "→ Endpoint quarantined. Full AV scan queued."
                ),
            },
            {
                "type": "webhook",
                "url": "http://edr-api/isolate",
                "method": "POST",
                "payload": {
                    "hostname": "{hostname}",
                    "reason": "malware",
                    "case_id": "{case_id}",
                },
            },
            {
                "type": "webhook",
                "url": "http://edr-api/scan",
                "method": "POST",
                "payload": {
                    "hostname": "{hostname}",
                    "scan_type": "full",
                    "case_id": "{case_id}",
                },
            },
            {
                "type": "webhook",
                "url": "http://soar/tickets",
                "method": "POST",
                "payload": {
                    "title": "Malware Infection — {case_id}",
                    "priority": "high",
                    "assignee": "soc-tier2",
                    "tags": ["malware", "edr", "quarantine"],
                    "case_id": "{case_id}",
                },
            },
        ],
    },

    # ── Privilege Escalation ─────────────────────────────────────────────────────
    {
        "name": "Privilege Escalation — Lock Account & Escalate",
        "description": (
            "Disables the compromised account via IAM, notifies SOC, "
            "and opens a high-priority investigation ticket."
        ),
        "trigger_decision": "True Positive",
        "trigger_min_confidence": 0.83,
        "trigger_attack_types": ["privilege_escalation"],
        "enabled": True,
        "actions": [
            {
                "type": "log",
                "message": "[PRIVESC] Case {case_id} — host {hostname} decision={decision} conf={confidence}",
            },
            {
                "type": "discord",
                "message": (
                    "⚠️ **PRIVILEGE ESCALATION** | Case `{case_id}`\n"
                    "Host: `{hostname}` | Confidence: **{confidence}**\n"
                    "→ Account locked. Audit all sessions from this host."
                ),
            },
            {
                "type": "webhook",
                "url": "http://iam-api/disable-account",
                "method": "POST",
                "payload": {
                    "hostname": "{hostname}",
                    "reason": "privilege_escalation",
                    "case_id": "{case_id}",
                    "force_logout": True,
                },
            },
            {
                "type": "webhook",
                "url": "http://soar/tickets",
                "method": "POST",
                "payload": {
                    "title": "Privilege Escalation — {case_id}",
                    "priority": "high",
                    "assignee": "soc-tier2",
                    "tags": ["privilege_escalation", "iam"],
                    "case_id": "{case_id}",
                },
            },
        ],
    },

    # ── Lateral Movement ─────────────────────────────────────────────────────────
    {
        "name": "Lateral Movement — Network Isolation",
        "description": (
            "Segments the affected subnet, notifies the SOC channel with kill-chain context, "
            "and opens a critical incident for full IR engagement."
        ),
        "trigger_decision": "True Positive",
        "trigger_min_confidence": 0.82,
        "trigger_attack_types": ["lateral_movement"],
        "enabled": True,
        "actions": [
            {
                "type": "log",
                "message": "[LATERAL] Case {case_id} — {hostname} / {source_ip} lateral movement confirmed",
            },
            {
                "type": "discord",
                "message": (
                    "🔄 **LATERAL MOVEMENT** | Case `{case_id}`\n"
                    "Host: `{hostname}` | IP: `{source_ip}`\n"
                    "Confidence: **{confidence}**\n"
                    "→ Network segment isolated. IR team engaged."
                ),
            },
            {
                "type": "webhook",
                "url": "http://network-api/isolate-segment",
                "method": "POST",
                "payload": {
                    "source_ip": "{source_ip}",
                    "hostname": "{hostname}",
                    "reason": "lateral_movement",
                    "case_id": "{case_id}",
                },
            },
            {
                "type": "webhook",
                "url": "http://soar/tickets",
                "method": "POST",
                "payload": {
                    "title": "Lateral Movement — {case_id}",
                    "priority": "critical",
                    "assignee": "ir-team",
                    "tags": ["lateral_movement", "network_isolation", "ir"],
                    "case_id": "{case_id}",
                },
            },
        ],
    },

    # ── Reconnaissance ───────────────────────────────────────────────────────────
    {
        "name": "Reconnaissance — Log & Monitor",
        "description": (
            "Logs confirmed recon activity and adds the source IP to a watchlist "
            "for elevated monitoring. Low-noise — no host isolation."
        ),
        "trigger_decision": "True Positive",
        "trigger_min_confidence": 0.78,
        "trigger_attack_types": ["reconnaissance"],
        "enabled": True,
        "actions": [
            {
                "type": "log",
                "message": "[RECON] Case {case_id} — source {source_ip} recon activity confirmed",
            },
            {
                "type": "webhook",
                "url": "http://threat-intel/watchlist",
                "method": "POST",
                "payload": {
                    "source_ip": "{source_ip}",
                    "reason": "reconnaissance",
                    "case_id": "{case_id}",
                    "monitor_days": 7,
                },
            },
            {
                "type": "webhook",
                "url": "http://soar/tickets",
                "method": "POST",
                "payload": {
                    "title": "Reconnaissance Activity — {case_id}",
                    "priority": "medium",
                    "assignee": "soc-tier1",
                    "tags": ["reconnaissance", "watchlist"],
                    "case_id": "{case_id}",
                },
            },
        ],
    },

    # ── Denial of Service ────────────────────────────────────────────────────────
    {
        "name": "Denial of Service — Rate-Limit & NOC Alert",
        "description": (
            "Applies rate-limiting rules via the WAF/load-balancer API, "
            "notifies both the SOC and NOC channels, and creates a high-priority ticket."
        ),
        "trigger_decision": "True Positive",
        "trigger_min_confidence": 0.80,
        "trigger_attack_types": ["denial_of_service"],
        "enabled": True,
        "actions": [
            {
                "type": "log",
                "message": "[DOS] Case {case_id} — source {source_ip} DoS/DDoS confirmed",
            },
            {
                "type": "discord",
                "message": (
                    "💥 **DENIAL OF SERVICE** | Case `{case_id}`\n"
                    "Source IP: `{source_ip}` | Confidence: **{confidence}**\n"
                    "→ Rate-limiting applied. NOC notified."
                ),
            },
            {
                "type": "webhook",
                "url": "http://waf-api/rate-limit",
                "method": "POST",
                "payload": {
                    "source_ip": "{source_ip}",
                    "action": "rate_limit",
                    "threshold_rpm": 100,
                    "case_id": "{case_id}",
                },
            },
            {
                "type": "webhook",
                "url": "http://soar/tickets",
                "method": "POST",
                "payload": {
                    "title": "DoS Attack — {case_id}",
                    "priority": "high",
                    "assignee": "noc-team",
                    "tags": ["dos", "waf", "rate_limiting"],
                    "case_id": "{case_id}",
                },
            },
        ],
    },

    # ── High-Confidence Catch-All ────────────────────────────────────────────────
    {
        "name": "High-Confidence Unknown — Generic Escalation",
        "description": (
            "Fallback for any True Positive with confidence >= 90% not covered by a specific playbook. "
            "Fires a Discord alert and opens an investigation ticket."
        ),
        "trigger_decision": "True Positive",
        "trigger_min_confidence": 0.90,
        "trigger_attack_types": None,
        "enabled": True,
        "actions": [
            {
                "type": "log",
                "message": "[HIGH-CONF] Case {case_id} — {attack_type} decision={decision} conf={confidence}",
            },
            {
                "type": "discord",
                "message": (
                    "🚨 **HIGH-CONFIDENCE THREAT** | Case `{case_id}`\n"
                    "Type: `{attack_type}` | Host: `{hostname}`\n"
                    "Confidence: **{confidence}** | Timestamp: {timestamp}\n"
                    "→ Manual triage required."
                ),
            },
            {
                "type": "webhook",
                "url": "http://soar/tickets",
                "method": "POST",
                "payload": {
                    "title": "High-Confidence Alert — {case_id}",
                    "priority": "high",
                    "assignee": "soc-tier2",
                    "tags": ["high_confidence", "manual_triage"],
                    "case_id": "{case_id}",
                    "attack_type": "{attack_type}",
                },
            },
        ],
    },
]


async def seed(base_url: str) -> None:
    created, skipped = 0, 0

    async with httpx.AsyncClient(timeout=15.0) as client:
        existing_resp = await client.get(f"{base_url}/playbooks")
        existing_resp.raise_for_status()
        existing_names = {pb["name"] for pb in existing_resp.json().get("playbooks", [])}

        for pb in PLAYBOOKS:
            if pb["name"] in existing_names:
                print(f"  SKIP (exists)  {pb['name']}")
                skipped += 1
                continue
            r = await client.post(f"{base_url}/playbooks", json=pb)
            if r.status_code == 201:
                data = r.json()["created"]
                print(f"  CREATED  id={data['id']:>3}  [{data['trigger_decision']} >= {data['trigger_min_confidence']:.0%}]  {pb['name']}")
                created += 1
            else:
                print(f"  ERROR {r.status_code}  {pb['name']}  —  {r.text[:120]}")

    print(f"\nDone — {created} created, {skipped} skipped.")


if __name__ == "__main__":
    asyncio.run(seed(BASE_URL))
