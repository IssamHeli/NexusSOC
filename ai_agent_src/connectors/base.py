from abc import ABC, abstractmethod
from typing import Any


class SIEMConnector(ABC):
    @abstractmethod
    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Normalize raw SIEM payload to SecurityAlert-compatible dict."""
        ...

    @property
    @abstractmethod
    def source_name(self) -> str:
        """Human-readable connector name."""
        ...


def _wazuh_level_to_severity(level: int) -> str:
    if level <= 4:   return "low"
    if level <= 8:   return "medium"
    if level <= 11:  return "high"
    return "critical"


def _magnitude_to_severity(magnitude: int) -> str:
    if magnitude <= 3:  return "low"
    if magnitude <= 6:  return "medium"
    if magnitude <= 8:  return "high"
    return "critical"


def _infer_attack_type(keywords: list[str]) -> str | None:
    k = " ".join(keywords).lower()
    if any(w in k for w in ["brute", "login fail", "auth fail", "password spray"]):
        return "brute_force"
    if any(w in k for w in ["exfil", "dlp", "data loss", "data transfer"]):
        return "data_exfiltration"
    if any(w in k for w in ["malware", "virus", "trojan", "ransomware", "backdoor", "c2"]):
        return "malware"
    if any(w in k for w in ["privilege", "escalat", "sudo", "uac bypass"]):
        return "privilege_escalation"
    if any(w in k for w in ["lateral", "smb", "wmi", "pass-the-hash", "mimikatz"]):
        return "lateral_movement"
    if any(w in k for w in ["recon", "scan", "discovery", "nmap", "enumerat"]):
        return "reconnaissance"
    if any(w in k for w in ["dos", "ddos", "flood", "denial"]):
        return "denial_of_service"
    return None
