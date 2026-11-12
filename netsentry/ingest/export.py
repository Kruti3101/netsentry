"""Write FlowRecords back out as Zeek conn.log (TSV) or nfdump-style CSV.

Used to turn replayed PCAPs into sample telemetry, and to feed the KQL
queries in ``queries/kql`` when testing in Azure Data Explorer / Sentinel.
"""
from __future__ import annotations

import csv
import gzip
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from ..models import FlowRecord

ZEEK_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration",
               "orig_bytes", "resp_bytes", "conn_state", "history", "orig_pkts", "resp_pkts"]


def _open(path: Path):
    return gzip.open(path, "wt", newline="") if path.suffix == ".gz" else path.open("w", newline="")


def _history(f: FlowRecord) -> str:
    h = ""
    if "S" in f.tcp_flags:
        h += "S"
    if f.conn_state in ("SF", "S1", "RSTO", "RSTR"):
        h += "hAD"
    if "F" in f.tcp_flags:
        h += "F"
    if "R" in f.tcp_flags or f.conn_state == "REJ":
        h += "r"
    return h or "-"


def write_zeek_conn(flows: Iterable[FlowRecord], path: str | Path) -> int:
    path = Path(path)
    n = 0
    with _open(path) as fh:
        fh.write("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n")
        fh.write("#fields\t" + "\t".join(ZEEK_FIELDS) + "\n")
        for i, f in enumerate(flows):
            row = [f"{f.ts:.6f}", f.uid or f"C{i:08x}", f.src, str(f.sport), f.dst, str(f.dport), f.proto,
                   f.service or "-", f"{f.duration:.6f}", str(f.orig_bytes), str(f.resp_bytes),
                   f.conn_state or "-", _history(f), str(f.orig_pkts), str(f.resp_pkts)]
            fh.write("\t".join(row) + "\n")
            n += 1
    return n


def _fmt(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _nf_flags(flags: str, proto: str) -> str:
    return "".join(c if c in flags else "." for c in "APRSF") if proto == "tcp" else "......"


def write_netflow_csv(flows: Iterable[FlowRecord], path: str | Path) -> int:
    """Unidirectional, like real NetFlow v5/v9: one record per direction."""
    path = Path(path)
    n = 0
    with _open(path) as fh:
        w = csv.writer(fh)
        w.writerow(["ts", "te", "td", "sa", "da", "sp", "dp", "pr", "flg", "ipkt", "ibyt"])
        for f in flows:
            span = [_fmt(f.ts), _fmt(f.ts + f.duration), f"{f.duration:.3f}"]
            w.writerow([*span, f.src, f.dst, f.sport, f.dport, f.proto.upper(),
                        _nf_flags(f.orig_flags or f.tcp_flags, f.proto), max(f.orig_pkts, 1), f.orig_bytes])
            n += 1
            if f.resp_pkts:
                w.writerow([*span, f.dst, f.src, f.dport, f.sport, f.proto.upper(),
                            _nf_flags(f.resp_flags, f.proto), f.resp_pkts, f.resp_bytes])
                n += 1
    return n
