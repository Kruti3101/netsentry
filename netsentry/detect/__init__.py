"""Detection pipeline: volumetric floods, scans and beaconing."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..config import Config
from ..models import Alert, FlowRecord
from .beacon import detect_beacons
from .floods import detect_volumetric
from .scan import detect_scans


@dataclass
class DetectionResult:
    alerts: list[Alert]
    baselines: dict = field(default_factory=dict)
    flows: int = 0


def run_detection(flows: list[FlowRecord], cfg: Config | None = None) -> DetectionResult:
    cfg = cfg or Config()
    flows = sorted(flows, key=lambda f: f.ts)
    vol, baselines = detect_volumetric(flows, cfg)
    alerts = vol + detect_scans(flows, cfg) + detect_beacons(flows, cfg)
    alerts.sort(key=lambda a: (a.ts_start, a.type))
    return DetectionResult(alerts=alerts, baselines=baselines, flows=len(flows))


__all__ = ["run_detection", "DetectionResult"]
