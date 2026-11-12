"""Pipeline configuration (YAML-overridable dataclasses)."""
from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass
class BaselineConfig:
    alpha: float = 0.1                # EWMA smoothing factor
    warmup_windows: int = 20          # windows before a service can alert
    z_threshold: float = 4.0          # flood z-score threshold
    anomaly_z_threshold: float = 6.0  # generic volume anomaly threshold
    rel_std_floor: float = 0.1        # std floor as a fraction of the mean
    max_freeze_windows: int = 30      # stop protecting baseline after a sustained shift


@dataclass
class FloodConfig:
    min_syn_per_window: int = 200
    min_syn_ratio: float = 0.6
    min_udp_pkts_per_window: int = 2000
    min_amp_bytes_per_window: int = 5_000_000
    # Absolute thresholds that fire even before a service has a baseline
    # (e.g. a flood aimed at a port that never saw traffic before).
    cold_start_syn_per_window: int = 2000
    cold_start_udp_pkts_per_window: int = 20000
    anomaly_min_flows: int = 50   # sparse services: tiny absolute changes give huge z-scores


@dataclass
class ScanConfig:
    window: float = 60.0
    vertical_ports: int = 50          # distinct ports on one host
    horizontal_hosts: int = 30        # distinct hosts on one port
    min_fail_ratio: float = 0.5


@dataclass
class BeaconConfig:
    min_connections: int = 8
    min_interval: float = 10.0        # ignore sub-10s chatter
    max_robust_cv: float = 0.2        # MAD/median of inter-arrival times
    ignore_ports: list[int] = field(default_factory=lambda: [53, 123, 5353])


@dataclass
class ResponseConfig:
    dry_run: bool = True
    allowlist: list[str] = field(default_factory=lambda: ["127.0.0.0/8"])
    min_confidence: float = 0.6
    block_ttl_seconds: int = 3600
    max_blocklist_size: int = 10_000
    syn_rate_limit_pps: int = 200     # per source, applied at the victim service
    udp_rate_limit_pps: int = 1000
    blocklist_path: str = "state/blocklist.json"
    nft_table: str = "netsentry"


@dataclass
class Config:
    window: float = 10.0
    internal_nets: list[str] = field(default_factory=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
    baseline: BaselineConfig = field(default_factory=BaselineConfig)
    flood: FloodConfig = field(default_factory=FloodConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    beacon: BeaconConfig = field(default_factory=BeaconConfig)
    response: ResponseConfig = field(default_factory=ResponseConfig)
    assets: dict[str, dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path | None) -> Config:
        if path is None:
            return cls()
        data = yaml.safe_load(Path(path).read_text()) or {}
        return _merge(cls(), data)


def _merge(obj, data: dict):
    for f in fields(obj):
        if f.name not in data:
            continue
        cur = getattr(obj, f.name)
        val = data[f.name]
        if is_dataclass(cur) and isinstance(val, dict):
            _merge(cur, val)
        else:
            setattr(obj, f.name, val)
    unknown = set(data) - {f.name for f in fields(obj)}
    if unknown:
        raise ValueError(f"unknown config keys for {type(obj).__name__}: {sorted(unknown)}")
    return obj
