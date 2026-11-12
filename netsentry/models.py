"""Core data models shared across the pipeline."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class FlowRecord:
    """A normalised connection/flow record.

    Zeek conn.log, NetFlow/IPFIX exports and PCAP-derived flows are all mapped
    onto this one shape so detectors never care where telemetry came from.
    """

    ts: float                 # flow start, epoch seconds
    src: str
    sport: int
    dst: str
    dport: int
    proto: str                # "tcp" | "udp" | "icmp"
    duration: float = 0.0
    orig_bytes: int = 0
    resp_bytes: int = 0
    orig_pkts: int = 0
    resp_pkts: int = 0
    conn_state: str = ""      # Zeek-style: S0, SF, REJ, RSTO, OTH ...
    tcp_flags: str = ""       # cumulative flags, e.g. "S", "SA", "SAFP"
    orig_flags: str = ""      # per-direction flags when known (PCAP-derived)
    resp_flags: str = ""
    service: str = ""         # Zeek service guess (http, dns, ssl ...)
    source: str = ""          # zeek | netflow | pcap
    uid: str = ""

    @property
    def total_pkts(self) -> int:
        return self.orig_pkts + self.resp_pkts

    @property
    def total_bytes(self) -> int:
        return self.orig_bytes + self.resp_bytes

    @property
    def is_syn_only(self) -> bool:
        """Half-open TCP attempt: SYN sent, no handshake completed."""
        if self.proto != "tcp":
            return False
        if self.conn_state:
            return self.conn_state in {"S0", "REJ", "RSTOS0", "SH"}
        flags = self.tcp_flags.upper()
        return "S" in flags and "A" not in flags

    @property
    def failed(self) -> bool:
        return self.conn_state in {"S0", "REJ", "RSTOS0", "RSTR", "SH", "OTH"} or (
            not self.conn_state and self.proto == "tcp" and self.is_syn_only
        )


@dataclass(slots=True)
class Technique:
    id: str
    name: str
    tactic: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class Alert:
    type: str                         # syn_flood | udp_flood | amplification | port_scan | beaconing | traffic_anomaly
    severity: str                     # low | medium | high | critical
    ts_start: float
    ts_end: float
    dst: str = ""
    dport: int | None = None
    proto: str = ""
    src: str = ""                     # single attributed source, if any
    top_sources: list[str] = field(default_factory=list)
    metrics: dict[str, float] = field(default_factory=dict)
    zscores: dict[str, float] = field(default_factory=dict)
    techniques: list[Technique] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.5
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            key = f"{self.type}|{self.src}|{self.dst}|{self.dport}|{self.proto}|{int(self.ts_start)}"
            self.id = "NS-" + hashlib.sha1(key.encode()).hexdigest()[:10]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["techniques"] = [t.to_dict() for t in self.techniques]
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Alert:
        d = dict(d)
        d["techniques"] = [Technique(**t) for t in d.get("techniques", [])]
        return cls(**d)
