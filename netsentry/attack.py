"""MITRE ATT&CK (Enterprise) mapping for NetSentry detections."""
from __future__ import annotations

from .models import Technique

CATALOG: dict[str, Technique] = {
    t.id: t
    for t in [
        Technique("T1498", "Network Denial of Service", "Impact"),
        Technique("T1498.001", "Network Denial of Service: Direct Network Flood", "Impact"),
        Technique("T1498.002", "Network Denial of Service: Reflection Amplification", "Impact"),
        Technique("T1499", "Endpoint Denial of Service", "Impact"),
        Technique("T1499.001", "Endpoint Denial of Service: OS Exhaustion Flood", "Impact"),
        Technique("T1046", "Network Service Discovery", "Discovery"),
        Technique("T1595.001", "Active Scanning: Scanning IP Blocks", "Reconnaissance"),
        Technique("T1071", "Application Layer Protocol", "Command and Control"),
        Technique("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
        Technique("T1071.004", "Application Layer Protocol: DNS", "Command and Control"),
        Technique("T1573", "Encrypted Channel", "Command and Control"),
        Technique("T1029", "Scheduled Transfer", "Exfiltration"),
    ]
}

# Short descriptions used as grounding context for LLM triage.
DESCRIPTIONS: dict[str, str] = {
    "T1498.001": "Adversary sends high volumes of traffic directly at a target to exhaust bandwidth (e.g. UDP floods).",
    "T1498.002": "Adversary spoofs the victim's address to third-party reflectors (DNS, NTP, memcached) whose larger responses flood the victim.",
    "T1499.001": "Adversary exhausts OS/stack resources, classically a TCP SYN flood filling the half-open connection backlog.",
    "T1046": "Adversary enumerates services on remote hosts, e.g. vertical/horizontal port scans with many failed connections.",
    "T1595.001": "External reconnaissance sweeping IP blocks before targeting.",
    "T1071": "C2 traffic blended into a standard application protocol.",
    "T1071.001": "C2 over HTTP/HTTPS, often as periodic beacons to an attacker-controlled server.",
    "T1071.004": "C2 tunnelled over DNS queries/responses.",
    "T1573": "C2 wrapped in an encrypted channel (TLS) to hide content.",
    "T1029": "Data or check-ins sent on a fixed schedule.",
}


def techniques_for(alert_type: str, *, dport: int | None = None, external_src: bool = False) -> list[Technique]:
    ids: list[str]
    if alert_type == "syn_flood":
        ids = ["T1499.001", "T1498"]
    elif alert_type == "udp_flood":
        ids = ["T1498.001"]
    elif alert_type == "amplification":
        ids = ["T1498.002"]
    elif alert_type == "port_scan":
        ids = ["T1046"] + (["T1595.001"] if external_src else [])
    elif alert_type == "beaconing":
        if dport in (80, 443, 8080, 8443):
            ids = ["T1071.001"] + (["T1573"] if dport in (443, 8443) else [])
        elif dport == 53:
            ids = ["T1071.004"]
        else:
            ids = ["T1071"]
    else:
        ids = []
    return [CATALOG[i] for i in ids]
