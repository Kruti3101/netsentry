"""Telemetry readers. Every reader yields :class:`netsentry.models.FlowRecord`."""
from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from ..models import FlowRecord
from .netflow import read_netflow_csv
from .zeek import read_conn_log


def load_flows(path: str | Path, kind: str = "auto") -> list[FlowRecord]:
    """Load flows from a Zeek conn.log, NetFlow CSV or PCAP, sorted by time."""
    path = Path(path)
    if kind == "auto":
        name = path.name.lower().removesuffix(".gz")
        if name.endswith((".pcap", ".cap", ".pcapng")):
            kind = "pcap"
        elif name.endswith(".csv"):
            kind = "netflow"
        else:
            kind = "zeek"
    flows: Iterable[FlowRecord]
    if kind == "zeek":
        flows = read_conn_log(path)
    elif kind == "netflow":
        flows = read_netflow_csv(path)
    elif kind == "pcap":
        from ..replay.flows import pcap_to_flows

        flows = pcap_to_flows(path)
    else:
        raise ValueError(f"unknown telemetry kind: {kind}")
    return sorted(flows, key=lambda f: f.ts)


__all__ = ["load_flows", "read_conn_log", "read_netflow_csv"]
