"""Horizontal and vertical port-scan detection."""
from __future__ import annotations

import ipaddress
from collections import defaultdict

from ..attack import techniques_for
from ..config import Config
from ..features import AMPLIFICATION_PORTS, is_response_flow
from ..models import Alert, FlowRecord


def in_nets(ip: str, nets: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(n, strict=False) for n in nets)


def detect_scans(flows: list[FlowRecord], cfg: Config) -> list[Alert]:
    sc = cfg.scan
    # src -> window -> aggregates
    agg: dict[str, dict[float, dict]] = defaultdict(dict)
    for f in flows:
        if f.proto not in ("tcp", "udp") or is_response_flow(f):
            continue
        if f.proto == "udp" and f.sport in AMPLIFICATION_PORTS:
            continue  # reflected responses spray random dports; that's amplification, not a scan
        w = f.ts - (f.ts % sc.window)
        a = agg[f.src].get(w)
        if a is None:
            a = agg[f.src][w] = {"ports_by_host": defaultdict(set), "hosts_by_port": defaultdict(set),
                                 "flows": 0, "failed": 0}
        a["ports_by_host"][f.dst].add(f.dport)
        a["hosts_by_port"][f.dport].add(f.dst)
        a["flows"] += 1
        a["failed"] += int(f.failed)

    alerts: list[Alert] = []
    for src, wins in agg.items():
        hits = []
        for w, a in sorted(wins.items()):
            fail_ratio = a["failed"] / a["flows"]
            vhost, vports = max(a["ports_by_host"].items(), key=lambda kv: len(kv[1]))
            hport, hhosts = max(a["hosts_by_port"].items(), key=lambda kv: len(kv[1]))
            vertical = len(vports) >= sc.vertical_ports
            horizontal = len(hhosts) >= sc.horizontal_hosts
            if (vertical or horizontal) and fail_ratio >= sc.min_fail_ratio:
                hits.append((w, a, vertical, horizontal, vhost, vports, hport, hhosts, fail_ratio))
        if not hits:
            continue
        start, end = hits[0][0], hits[-1][0] + sc.window
        kinds = sorted({k for h in hits for k, on in (("vertical", h[2]), ("horizontal", h[3])) if on})
        peak_ports = max(len(h[5]) for h in hits)
        peak_hosts = max(len(h[7]) for h in hits)
        all_targets = {h[4] for h in hits if h[2]}
        port_targets = {h[6] for h in hits if h[3]}
        fail = max(h[8] for h in hits)
        external = not in_nets(src, cfg.internal_nets)
        dst = next(iter(all_targets)) if len(all_targets) == 1 else ""
        dport = next(iter(port_targets)) if len(port_targets) == 1 and not dst else None
        severity = "high" if (external and peak_ports >= 500) or peak_hosts >= 250 else "medium"
        conf = min(0.95, 0.6 + 0.1 * len(hits) + (0.1 if fail > 0.9 else 0))
        alerts.append(Alert(
            type="port_scan",
            severity=severity,
            ts_start=start,
            ts_end=end,
            src=src,
            dst=dst,
            dport=dport,
            proto="tcp",
            top_sources=[src],
            metrics={"peak_ports_one_host": peak_ports, "peak_hosts_one_port": peak_hosts,
                     "fail_ratio": round(fail, 3), "windows": len(hits)},
            techniques=techniques_for("port_scan", external_src=external),
            evidence=[
                f"{'/'.join(kinds)} scan from {src} ({'external' if external else 'internal'})",
                f"peak {peak_ports} distinct ports on one host, {peak_hosts} distinct hosts on one port "
                f"per {int(sc.window)}s window",
                f"failed-connection ratio {fail:.2f} over {len(hits)} window(s)",
            ],
            confidence=round(conf, 2),
        ))
    return alerts
