"""Per-service volumetric detection: SYN floods, UDP floods, reflection
amplification and generic traffic anomalies, driven by EWMA z-scores."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from ..attack import techniques_for
from ..config import Config
from ..features import AMPLIFICATION_PORTS, WindowStats, window_flows
from ..models import Alert, FlowRecord
from .baseline import ServiceBaseline

METRICS = ["flows", "pkts", "bytes", "syn_only", "unique_src"]


@dataclass
class _Open:
    """An alert being extended across consecutive anomalous windows."""
    type: str
    start: float
    end: float
    peak_z: dict[str, float] = field(default_factory=dict)
    peak: dict[str, float] = field(default_factory=dict)
    sources: dict[str, int] = field(default_factory=dict)
    windows: int = 0
    total_pkts: int = 0
    cold_start: bool = False
    top_share: float = 0.0


def _classify(proto: str, vec: dict[str, float], z: dict[str, float] | None, cfg: Config) -> tuple[str | None, bool]:
    """Return (alert_type, cold_start) for one window, or (None, False)."""
    b, fl = cfg.baseline, cfg.flood
    if z is None:
        # No baseline yet: only very blatant SYN floods qualify.
        if proto == "tcp" and vec["syn_only"] >= fl.cold_start_syn_per_window and vec["syn_ratio"] >= fl.min_syn_ratio:
            return "syn_flood", True
        if proto == "udp" and vec["pkts"] >= fl.cold_start_udp_pkts_per_window:
            return "udp_flood", True
        if proto == "udp-amp" and vec["bytes"] >= fl.min_amp_bytes_per_window:
            return "amplification", True
        return None, False
    if proto == "tcp" and z["syn_only"] >= b.z_threshold and vec["syn_only"] >= fl.min_syn_per_window \
            and vec["syn_ratio"] >= fl.min_syn_ratio:
        return "syn_flood", False
    if proto == "udp" and max(z["pkts"], z["bytes"]) >= b.z_threshold and vec["pkts"] >= fl.min_udp_pkts_per_window:
        return "udp_flood", False
    if proto == "udp-amp" and z["bytes"] >= b.z_threshold and vec["bytes"] >= fl.min_amp_bytes_per_window:
        return "amplification", False
    if max(z["flows"], z["pkts"], z["bytes"]) >= b.anomaly_z_threshold and vec["flows"] >= fl.anomaly_min_flows:
        return "traffic_anomaly", False
    return None, False


def detect_volumetric(flows: list[FlowRecord], cfg: Config) -> tuple[list[Alert], dict]:
    """Run baselines over every service. Returns alerts and final baseline snapshots."""
    nets = [ipaddress.ip_network(n, strict=False) for n in cfg.internal_nets]

    def internal(ip: str) -> bool:
        try:
            return any(ipaddress.ip_address(ip) in n for n in nets)
        except ValueError:
            return False

    windows, per_service = window_flows(flows, cfg.window, internal)
    alerts: list[Alert] = []
    snapshots: dict[str, dict] = {}
    b = cfg.baseline

    for (dst, dport, proto), buckets in per_service.items():
        model = ServiceBaseline(METRICS, b.alpha, b.warmup_windows, b.rel_std_floor, b.max_freeze_windows)
        first = min(buckets)
        open_: _Open | None = None

        for w in windows:
            if w < first:
                continue
            stats = buckets.get(w) or WindowStats()
            vec = stats.vector()
            z = model.score(vec)
            kind, cold = _classify(proto, vec, z, cfg)
            if kind:
                if open_ and open_.type == kind:
                    open_.end = w + cfg.window
                else:
                    if open_:
                        alerts.append(_to_alert(open_, dst, dport, proto, cfg))
                    open_ = _Open(kind, w, w + cfg.window, cold_start=cold)
                open_.windows += 1
                open_.total_pkts += stats.pkts
                for m, v in vec.items():
                    open_.peak[m] = max(open_.peak.get(m, 0.0), v)
                for m, v in (z or {}).items():
                    open_.peak_z[m] = max(open_.peak_z.get(m, float("-inf")), round(v, 2))
                for s in stats.top_sources(10):
                    open_.sources[s] = open_.sources.get(s, 0) + stats.src_pkts[s]
                open_.top_share = max(open_.top_share, stats.top_source_share())
            elif open_:
                alerts.append(_to_alert(open_, dst, dport, proto, cfg))
                open_ = None
            model.observe(vec, anomalous=kind is not None and kind != "traffic_anomaly")
        if open_:
            alerts.append(_to_alert(open_, dst, dport, proto, cfg))
        snapshots[f"{dst}:{abs(dport)}/{proto}"] = model.snapshot()
    alerts.sort(key=lambda a: a.ts_start)
    return alerts, snapshots


def _to_alert(o: _Open, dst: str, dport: int, proto: str, cfg: Config) -> Alert:
    zt = cfg.baseline.z_threshold
    top_z = max(o.peak_z.values()) if o.peak_z else 0.0
    if o.type == "traffic_anomaly":
        severity, conf = "low", 0.4
    elif o.cold_start:
        severity, conf = "high", 0.65
    else:
        severity = "critical" if top_z >= 3 * zt else "high"
        conf = min(0.99, 0.6 + 0.04 * (top_z - zt) + 0.02 * o.windows)
    total = o.total_pkts or 1
    # Only attribute sources carrying >=1% of anomalous packets; this keeps
    # legitimate clients that happen to be talking to the victim out of the list.
    srcs = [s for s, n in sorted(o.sources.items(), key=lambda kv: -kv[1])[:10] if n / total >= 0.01]
    real_proto = "udp" if proto == "udp-amp" else proto
    evidence = [
        f"{o.windows} consecutive {int(cfg.window)}s windows anomalous for {dst}:{abs(dport)}/{proto}",
        "peak metrics: " + ", ".join(f"{k}={v:.3g}" for k, v in sorted(o.peak.items())),
    ]
    if o.peak_z:
        evidence.append("peak z-scores: " + ", ".join(f"{k}={v}" for k, v in sorted(o.peak_z.items())))
    if o.cold_start:
        evidence.append("no baseline yet for this service; fired on absolute cold-start threshold")
    if proto == "udp-amp":
        evidence.append(f"reflected traffic from {AMPLIFICATION_PORTS.get(-dport, '?')} (udp/{-dport}) reflectors")
    evidence.append(f"top source share of packets: {o.top_share:.2f}; distinct top sources: {len(o.sources)}")
    return Alert(
        type=o.type,
        severity=severity,
        ts_start=o.start,
        ts_end=o.end,
        dst=dst,
        dport=abs(dport),
        proto=real_proto,
        top_sources=srcs,
        metrics={**{k: round(v, 3) for k, v in o.peak.items()}, "windows": o.windows,
                 "top_source_share": round(o.top_share, 3)},
        zscores=o.peak_z,
        techniques=techniques_for(o.type),
        evidence=evidence,
        confidence=round(conf, 2),
    )
