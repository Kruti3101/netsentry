"""Replay labelled PCAPs through detection + response and score the outcome.

A scenario manifest (YAML) lists PCAPs with the detections and actions that
*must* happen, detections that must *not* happen, and IPs that must never be
blocked. The harness reports pass/fail, time-to-detect and the response plan.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ..config import Config
from ..detect import run_detection
from ..models import Alert
from ..respond import plan_response
from .flows import pcap_to_flows


@dataclass
class ScenarioResult:
    name: str
    passed: bool
    flows: int
    alerts: list[Alert]
    checks: list[tuple[str, bool]] = field(default_factory=list)
    ttd_seconds: float | None = None
    actions: list[dict] = field(default_factory=list)


def _match(alert: Alert, spec: dict) -> bool:
    for k, v in spec.items():
        if k == "technique":
            if v not in {t.id for t in alert.techniques}:
                return False
        elif getattr(alert, k, None) != v:
            return False
    return True


def run_scenario(name: str, spec: dict, cfg: Config, base_dir: Path) -> ScenarioResult:
    flows = pcap_to_flows(base_dir / spec["pcap"])
    det = run_detection(flows, cfg)
    plan = plan_response(det.alerts, cfg)
    actions = [a.to_dict() for a in plan.actions]
    checks: list[tuple[str, bool]] = []
    ttd = None
    attack_start = spec.get("attack_start")

    for exp in spec.get("expect", []):
        exp = dict(exp)
        start = exp.pop("start", attack_start)   # per-expectation override
        hits = [a for a in det.alerts if _match(a, exp)]
        checks.append((f"detects {exp}", bool(hits)))
        if hits and start is not None:
            first = min(hits, key=lambda a: a.ts_start)
            # an alert is raised when its first window closes
            window = cfg.scan.window if first.type == "port_scan" else cfg.window
            ttd_i = max(0.0, first.ts_start + window - start)
            ttd = ttd_i if ttd is None else max(ttd, ttd_i)
    for exp in spec.get("expect_not", []):
        hits = [a for a in det.alerts if _match(a, exp)]
        checks.append((f"no {exp}", not hits))
    for exp in spec.get("expect_actions", []):
        ok = any(all(a.get(k) == v for k, v in exp.items()) for a in actions)
        checks.append((f"action {exp}", ok))
    for ip in spec.get("never_block", []):
        bad = [a for a in actions if a["kind"].startswith("block") and a["target"] == ip and not a["requires_approval"]]
        checks.append((f"never auto-blocks {ip}", not bad))
    if "max_alerts" in spec:
        checks.append((f"<= {spec['max_alerts']} alerts", len(det.alerts) <= spec["max_alerts"]))

    return ScenarioResult(name, all(ok for _, ok in checks), len(flows), det.alerts, checks, ttd, actions)


def run_manifest(manifest: str | Path, cfg: Config | None = None) -> list[ScenarioResult]:
    manifest = Path(manifest)
    data = yaml.safe_load(manifest.read_text())
    cfg = cfg or Config()
    base = manifest.parent / data.get("pcap_dir", ".")
    return [run_scenario(name, spec, cfg, base) for name, spec in data["scenarios"].items()]


def format_results(results: list[ScenarioResult]) -> str:
    lines = [f"{'scenario':<15} {'result':<6} {'flows':>7} {'alerts':>6} {'TTD(s)':>7}  actions",
             "-" * 72]
    for r in results:
        ttd = f"{r.ttd_seconds:.0f}" if r.ttd_seconds is not None else "-"
        acts = ", ".join(sorted({f"{a['kind']}:{a['target']}" for a in r.actions})) or "none"
        lines.append(f"{r.name:<15} {'PASS' if r.passed else 'FAIL':<6} {r.flows:>7} {len(r.alerts):>6} {ttd:>7}  {acts}")
        for desc, ok in r.checks:
            if not ok:
                lines.append(f"    x {desc}")
    passed = sum(r.passed for r in results)
    lines.append("-" * 72)
    lines.append(f"{passed}/{len(results)} scenarios passed")
    return "\n".join(lines)
