"""NetFlow / IPFIX CSV reader.

Accepts `nfdump -o csv` output as well as generic flow CSVs; column names are
resolved through an alias table so most collectors' exports work unmodified.
"""
from __future__ import annotations

import csv
import gzip
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from ..models import FlowRecord

ALIASES: dict[str, tuple[str, ...]] = {
    "ts": ("ts", "first", "start", "timestamp", "flow_start", "time"),
    "te": ("te", "last", "end", "flow_end"),
    "td": ("td", "duration", "dur"),
    "src": ("sa", "src", "srcaddr", "src_ip", "ipv4_src_addr", "sourceipv4address"),
    "dst": ("da", "dst", "dstaddr", "dst_ip", "ipv4_dst_addr", "destinationipv4address"),
    "sport": ("sp", "sport", "srcport", "src_port", "l4_src_port"),
    "dport": ("dp", "dport", "dstport", "dst_port", "l4_dst_port"),
    "proto": ("pr", "proto", "protocol"),
    "flags": ("flg", "flags", "tcp_flags", "tcpflags"),
    "ipkt": ("ipkt", "pkts", "packets", "in_pkts", "dpkts"),
    "ibyt": ("ibyt", "bytes", "octets", "in_bytes", "doctets"),
    "opkt": ("opkt", "out_pkts"),
    "obyt": ("obyt", "out_bytes"),
}

_PROTO_NUM = {"6": "tcp", "17": "udp", "1": "icmp"}


def _parse_ts(v: str) -> float:
    v = v.strip()
    try:
        return float(v)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(v.rstrip("Z"), fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    raise ValueError(f"unparseable timestamp: {v!r}")


def _flags(v: str) -> str:
    """nfdump renders flags like '...A.S.' or '.AP.SF'; also accept int bitmasks."""
    v = (v or "").strip()
    if not v:
        return ""
    if v.isdigit():
        n = int(v)
        out = ""
        for bit, ch in ((0x02, "S"), (0x10, "A"), (0x01, "F"), (0x04, "R"), (0x08, "P")):
            if n & bit:
                out += ch
        return out
    return "".join(ch for ch in "SAFRP" if ch in v.upper())


def read_netflow_csv(path: str | Path) -> Iterator[FlowRecord]:
    path = Path(path)
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            return
        lower = {f.strip().lower(): f for f in reader.fieldnames}
        col = {}
        for key, names in ALIASES.items():
            for n in names:
                if n in lower:
                    col[key] = lower[n]
                    break
        missing = {"ts", "src", "dst"} - col.keys()
        if missing:
            raise ValueError(f"{path}: missing required columns {sorted(missing)}")

        def g(row, key, default=""):
            c = col.get(key)
            return row.get(c, default) if c else default

        for row in reader:
            ts_raw = g(row, "ts")
            if not ts_raw or ts_raw.lower() in {"summary", "ts"}:
                continue  # nfdump appends a summary block
            try:
                ts = _parse_ts(ts_raw)
            except ValueError:
                continue
            proto = str(g(row, "proto")).strip().lower()
            proto = _PROTO_NUM.get(proto, proto)
            dur = g(row, "td")
            if not dur and g(row, "te"):
                dur = _parse_ts(g(row, "te")) - ts
            flags = _flags(g(row, "flags"))
            yield FlowRecord(
                ts=ts,
                src=g(row, "src").strip(),
                sport=int(float(g(row, "sport") or 0)),
                dst=g(row, "dst").strip(),
                dport=int(float(g(row, "dport") or 0)),
                proto=proto,
                duration=float(dur or 0),
                orig_pkts=int(float(g(row, "ipkt") or 0)),
                orig_bytes=int(float(g(row, "ibyt") or 0)),
                resp_pkts=int(float(g(row, "opkt") or 0)),
                resp_bytes=int(float(g(row, "obyt") or 0)),
                tcp_flags=flags,
                source="netflow",
            )
