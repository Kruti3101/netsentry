"""Windowed per-service feature extraction.

A *service* is the server side of a conversation: (dst, dport, proto). Each
fixed-size time window yields one feature vector per service, which feeds the
per-service EWMA baselines in :mod:`netsentry.detect.baseline`.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from .models import FlowRecord

# UDP services commonly abused for reflection/amplification.
AMPLIFICATION_PORTS = {
    19: "chargen", 53: "dns", 123: "ntp", 161: "snmp", 389: "cldap",
    1900: "ssdp", 11211: "memcached", 3702: "ws-discovery",
}

ServiceKey = tuple[str, int, str]   # (dst, dport, proto)


@dataclass
class WindowStats:
    flows: int = 0
    pkts: int = 0
    bytes: int = 0
    syn_only: int = 0
    failed: int = 0
    sources: set[str] = field(default_factory=set)
    src_pkts: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def add(self, f: FlowRecord) -> None:
        self.flows += 1
        pk = max(f.total_pkts, 1)
        self.pkts += pk
        self.bytes += f.total_bytes
        self.syn_only += int(f.is_syn_only)
        self.failed += int(f.failed)
        self.sources.add(f.src)
        self.src_pkts[f.src] += pk

    def vector(self) -> dict[str, float]:
        return {
            "flows": float(self.flows),
            "pkts": float(self.pkts),
            "bytes": float(self.bytes),
            "syn_only": float(self.syn_only),
            "unique_src": float(len(self.sources)),
            "syn_ratio": self.syn_only / self.flows if self.flows else 0.0,
            "fail_ratio": self.failed / self.flows if self.flows else 0.0,
        }

    def top_sources(self, k: int = 5) -> list[str]:
        return [s for s, _ in sorted(self.src_pkts.items(), key=lambda kv: -kv[1])[:k]]

    def top_source_share(self) -> float:
        if not self.pkts:
            return 0.0
        return max(self.src_pkts.values()) / self.pkts


def is_response_flow(f: FlowRecord) -> bool:
    """Unidirectional exports (NetFlow) carry server->client flows as separate
    records. Treat 'well-known sport -> ephemeral dport' as the reverse leg."""
    return bool(f.sport) and f.sport < 1024 and f.dport >= 1024 and f.sport not in AMPLIFICATION_PORTS


def service_key(f: FlowRecord, internal: Callable[[str], bool] | None = None) -> ServiceKey | None:
    if f.proto == "udp" and f.sport in AMPLIFICATION_PORTS and f.dport not in AMPLIFICATION_PORTS:
        if internal and internal(f.src):
            return None  # our own resolver/NTP server answering clients
        # Reflected traffic arriving at the victim: key on the abused service.
        return (f.dst, -f.sport, "udp-amp")
    if is_response_flow(f):
        return None
    return (f.dst, f.dport, f.proto)


def window_flows(
    flows: Iterable[FlowRecord], window: float, internal: Callable[[str], bool] | None = None
) -> tuple[list[float], dict[ServiceKey, dict[float, WindowStats]]]:
    """Bucket flows into fixed windows per service.

    Returns the sorted list of window start times (contiguous, gaps filled) and
    a mapping service -> window_start -> stats. Missing windows mean zero traffic.
    """
    per: dict[ServiceKey, dict[float, WindowStats]] = defaultdict(dict)
    lo = hi = None
    for f in flows:
        key = service_key(f, internal)
        w = f.ts - (f.ts % window)
        lo = w if lo is None else min(lo, w)
        hi = w if hi is None else max(hi, w)
        if key is None:
            continue
        bucket = per[key].get(w)
        if bucket is None:
            bucket = per[key][w] = WindowStats()
        bucket.add(f)
    if lo is None:
        return [], {}
    n = int(round((hi - lo) / window)) + 1
    return [lo + i * window for i in range(n)], per
