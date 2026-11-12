"""Turn alerts into response actions, with guardrails.

Guardrails (in order):
  * confidence below ``min_confidence`` -> no action, logged as skipped
  * targets in the allowlist are never blocked or limited
  * the victim of a flood is never blocked (we rate-limit *towards* it)
  * internal hosts are never auto-blocked; the action is emitted with
    ``requires_approval=True`` so a human confirms the quarantine
  * a single plan never exceeds ``max_blocklist_size`` block entries
"""
from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field

from ..config import Config
from ..detect.scan import in_nets
from ..features import AMPLIFICATION_PORTS
from ..models import Alert


@dataclass
class Action:
    kind: str                    # rate_limit | block_src | block_dst | drop_reflection
    alert_id: str
    reason: str
    target: str = ""             # IP the action applies to
    dst: str = ""
    dport: int | None = None
    sport: int | None = None
    proto: str = ""
    pps: int | None = None
    ttl: int | None = None
    requires_approval: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Plan:
    actions: list[Action] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)


def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def plan_response(alerts: list[Alert], cfg: Config) -> Plan:
    rc = cfg.response
    plan = Plan()
    blocked: set[str] = set()

    def skip(alert: Alert, why: str, target: str = "") -> None:
        plan.skipped.append({"alert_id": alert.id, "type": alert.type, "target": target, "reason": why})

    def block(alert: Alert, kind: str, ip: str, why: str) -> None:
        if not _valid_ip(ip):
            return skip(alert, "invalid ip", ip)
        if in_nets(ip, rc.allowlist):
            return skip(alert, "allowlisted", ip)
        if kind == "block_src" and ip == alert.dst:
            return skip(alert, "refusing to block the victim", ip)
        if ip in blocked:
            return
        if len(blocked) >= rc.max_blocklist_size:
            return skip(alert, "blocklist size cap reached", ip)
        blocked.add(ip)
        plan.actions.append(Action(kind=kind, alert_id=alert.id, reason=why, target=ip, ttl=rc.block_ttl_seconds,
                                   requires_approval=in_nets(ip, cfg.internal_nets)))

    for a in alerts:
        if a.confidence < rc.min_confidence:
            skip(a, f"confidence {a.confidence} < {rc.min_confidence}")
            continue
        if a.dst and in_nets(a.dst, rc.allowlist) and a.type in ("syn_flood", "udp_flood", "amplification"):
            skip(a, "victim is allowlisted for automated mitigation", a.dst)
            continue

        if a.type == "syn_flood":
            plan.actions.append(Action("rate_limit", a.id, "per-source SYN rate limit at victim service",
                                       target=a.dst, dst=a.dst, dport=a.dport, proto="tcp",
                                       pps=rc.syn_rate_limit_pps))
            # Spoofed floods spread across thousands of sources; only block if
            # traffic is concentrated enough that sources are likely real.
            if a.metrics.get("top_source_share", 0) >= 0.5 and a.top_sources:
                block(a, "block_src", a.top_sources[0], "dominant SYN flood source")
        elif a.type == "udp_flood":
            plan.actions.append(Action("rate_limit", a.id, "per-source UDP rate limit at victim service",
                                       target=a.dst, dst=a.dst, dport=a.dport, proto="udp",
                                       pps=rc.udp_rate_limit_pps))
            if len(a.top_sources) <= 10:
                for s in a.top_sources:
                    block(a, "block_src", s, "UDP flood source (small botnet)")
        elif a.type == "amplification":
            sport = a.dport  # for reflection alerts dport carries the abused service port
            plan.actions.append(Action("drop_reflection", a.id,
                                       f"drop unsolicited {AMPLIFICATION_PORTS.get(sport, 'udp')} responses",
                                       target=a.dst, dst=a.dst, sport=sport, proto="udp"))
        elif a.type == "port_scan":
            block(a, "block_src", a.src, "port scanning source")
        elif a.type == "beaconing":
            if a.severity in ("high", "critical"):
                block(a, "block_dst", a.dst, f"suspected C2 endpoint contacted by {a.src}")
            else:
                skip(a, "beacon severity below auto-block threshold", a.dst)
        else:
            skip(a, "informational alert type; notify only")
    return plan
