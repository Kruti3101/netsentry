"""Zeek conn.log reader (TSV with #fields header, or JSON-lines)."""
from __future__ import annotations

import gzip
import json
from collections.abc import Iterator
from pathlib import Path

from ..models import FlowRecord

_UNSET = {"-", "(empty)", ""}


def _num(v, cast=float, default=0):
    if v is None or (isinstance(v, str) and v in _UNSET):
        return default
    try:
        return cast(v)
    except (TypeError, ValueError):
        return default


def _from_mapping(row: dict) -> FlowRecord:
    return FlowRecord(
        ts=_num(row.get("ts"), float, 0.0),
        uid=str(row.get("uid", "")),
        src=str(row.get("id.orig_h", "")),
        sport=_num(row.get("id.orig_p"), int, 0),
        dst=str(row.get("id.resp_h", "")),
        dport=_num(row.get("id.resp_p"), int, 0),
        proto=str(row.get("proto", "")).lower(),
        service="" if row.get("service") in _UNSET or row.get("service") is None else str(row["service"]),
        duration=_num(row.get("duration"), float, 0.0),
        orig_bytes=_num(row.get("orig_bytes"), int, 0),
        resp_bytes=_num(row.get("resp_bytes"), int, 0),
        orig_pkts=_num(row.get("orig_pkts"), int, 0),
        resp_pkts=_num(row.get("resp_pkts"), int, 0),
        conn_state="" if row.get("conn_state") in _UNSET or row.get("conn_state") is None else str(row["conn_state"]),
        tcp_flags=_history_to_flags(str(row.get("history", "") or "")),
        source="zeek",
    )


def _history_to_flags(history: str) -> str:
    """Approximate cumulative TCP flags from Zeek's `history` string."""
    if history in _UNSET:
        return ""
    h = history.upper()
    flags = ""
    if "S" in h:
        flags += "S"
    if "H" in h or "A" in h or "D" in h:
        flags += "A"
    if "F" in h:
        flags += "F"
    if "R" in h:
        flags += "R"
    return flags


def read_conn_log(path: str | Path) -> Iterator[FlowRecord]:
    path = Path(path)
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
        first = fh.readline()
        fh.seek(0)
        if first.lstrip().startswith("{"):
            for line in fh:
                line = line.strip()
                if line:
                    yield _from_mapping(json.loads(line))
            return

        fields: list[str] = []
        sep = "\t"
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("#separator"):
                raw = line.split(" ", 1)[1].strip()
                sep = bytes(raw, "utf-8").decode("unicode_escape")
                continue
            if line.startswith("#fields"):
                fields = line.split(sep)[1:]
                continue
            if line.startswith("#") or not line:
                continue
            if not fields:
                raise ValueError(f"{path}: data row before #fields header")
            yield _from_mapping(dict(zip(fields, line.split(sep))))
