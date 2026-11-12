"""C2 beaconing detection from connection periodicity.

Implants typically check in on a timer with small jitter. For every
internal->external (src, dst, dport) pair we look at the inter-arrival times
and use a robust coefficient of variation (MAD / median) so a few missed or
delayed check-ins don't hide an otherwise regular cadence.
"""
from __future__ import annotations

import statistics
from collections import defaultdict

from ..attack import techniques_for
from ..config import Config
from ..models import Alert, FlowRecord
from .scan import in_nets


def _robust_cv(xs: list[float]) -> float:
    med = statistics.median(xs)
    if med <= 0:
        return float("inf")
    mad = statistics.median(abs(x - med) for x in xs)
    return 1.4826 * mad / med   # scaled MAD ~ std for normal data


def detect_beacons(flows: list[FlowRecord], cfg: Config) -> list[Alert]:
    bc = cfg.beacon
    groups: dict[tuple[str, str, int, str], list[FlowRecord]] = defaultdict(list)
    for f in flows:
        if f.dport in bc.ignore_ports:
            continue
        if not in_nets(f.src, cfg.internal_nets) or in_nets(f.dst, cfg.internal_nets):
            continue
        groups[(f.src, f.dst, f.dport, f.proto)].append(f)

    alerts: list[Alert] = []
    for (src, dst, dport, proto), fs in groups.items():
        if len(fs) < bc.min_connections:
            continue
        ts = sorted(f.ts for f in fs)
        deltas = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0]
        if len(deltas) < bc.min_connections - 1:
            continue
        median_iv = statistics.median(deltas)
        if median_iv < bc.min_interval:
            continue
        rcv = _robust_cv(deltas)
        if rcv > bc.max_robust_cv:
            continue
        sizes = [f.orig_bytes for f in fs]
        size_cv = statistics.pstdev(sizes) / statistics.mean(sizes) if statistics.mean(sizes) else 0.0
        score = round((1 - rcv / bc.max_robust_cv) * 0.7 + max(0.0, 1 - size_cv) * 0.3, 3)
        conf = round(min(0.95, 0.55 + 0.4 * score + 0.01 * min(len(fs), 20)), 2)
        alerts.append(Alert(
            type="beaconing",
            severity="high" if score >= 0.6 else "medium",
            ts_start=ts[0],
            ts_end=ts[-1],
            src=src,
            dst=dst,
            dport=dport,
            proto=proto,
            top_sources=[src],
            metrics={
                "connections": len(fs),
                "median_interval_s": round(median_iv, 2),
                "robust_cv": round(rcv, 4),
                "bytes_cv": round(size_cv, 4),
                "beacon_score": score,
            },
            techniques=techniques_for("beaconing", dport=dport),
            evidence=[
                f"{len(fs)} connections {src} -> {dst}:{dport}/{proto} over {ts[-1] - ts[0]:.0f}s",
                f"median inter-arrival {median_iv:.1f}s, robust CV {rcv:.3f} (threshold {bc.max_robust_cv})",
                f"request size CV {size_cv:.3f}",
            ],
            confidence=conf,
        ))
    return alerts
