"""Assemble packets into bidirectional flows with Zeek-like conn_state."""
from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from ..models import FlowRecord
from .pcap import TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, Packet, read_pcap


@dataclass
class _Flow:
    ts: float
    last: float
    src: str
    sport: int
    dst: str
    dport: int
    proto: str
    orig_pkts: int = 0
    resp_pkts: int = 0
    orig_bytes: int = 0
    resp_bytes: int = 0
    orig_flags: int = 0
    resp_flags: int = 0

    def conn_state(self) -> str:
        if self.proto != "tcp":
            return "SF" if self.resp_pkts else "S0"
        o, r = self.orig_flags, self.resp_flags
        if o & TCP_SYN and not self.resp_pkts:
            return "S0"
        if o & TCP_SYN and r & TCP_RST and not r & TCP_SYN:
            return "REJ"
        if o & TCP_SYN and r & TCP_SYN and r & TCP_ACK:
            if (o | r) & TCP_RST:
                return "RSTO" if o & TCP_RST else "RSTR"
            return "SF" if (o | r) & TCP_FIN else "S1"
        return "OTH"

    def to_record(self) -> FlowRecord:
        def fl(bits: int) -> str:
            return "".join(ch for bit, ch in ((TCP_SYN, "S"), (TCP_ACK, "A"), (TCP_FIN, "F"), (TCP_RST, "R"))
                           if bits & bit)
        flags = fl(self.orig_flags | self.resp_flags)
        return FlowRecord(
            ts=self.ts, src=self.src, sport=self.sport, dst=self.dst, dport=self.dport, proto=self.proto,
            duration=round(self.last - self.ts, 6), orig_bytes=self.orig_bytes, resp_bytes=self.resp_bytes,
            orig_pkts=self.orig_pkts, resp_pkts=self.resp_pkts, conn_state=self.conn_state(),
            tcp_flags=flags, orig_flags=fl(self.orig_flags), resp_flags=fl(self.resp_flags), source="pcap",
        )


def assemble(packets: Iterable[Packet], idle_timeout: float = 60.0) -> Iterator[FlowRecord]:
    table: dict[tuple, _Flow] = {}
    last_sweep = None
    for p in packets:
        fwd = (p.proto, p.src, p.sport, p.dst, p.dport)
        rev = (p.proto, p.dst, p.dport, p.src, p.sport)
        fl = table.get(fwd)
        direction = "o"
        if fl is None and rev in table:
            fl, direction = table[rev], "r"
        if fl is not None and p.ts - fl.last > idle_timeout:
            yield table.pop(fwd if direction == "o" else rev).to_record()
            fl = None
        if fl is None:
            # a bare SYN-ACK starts no flow of its own; it belongs to the client.
            fl = table[fwd] = _Flow(p.ts, p.ts, p.src, p.sport, p.dst, p.dport, p.proto)
            direction = "o"
        fl.last = p.ts
        if direction == "o":
            fl.orig_pkts += 1
            fl.orig_bytes += p.payload_len
            fl.orig_flags |= p.flags
        else:
            fl.resp_pkts += 1
            fl.resp_bytes += p.payload_len
            fl.resp_flags |= p.flags
        if last_sweep is None or p.ts - last_sweep > idle_timeout:
            last_sweep = p.ts
            for k in [k for k, v in table.items() if p.ts - v.last > idle_timeout]:
                yield table.pop(k).to_record()
    for v in table.values():
        yield v.to_record()


def pcap_to_flows(path: str | Path, idle_timeout: float = 60.0) -> list[FlowRecord]:
    return sorted(assemble(read_pcap(path), idle_timeout), key=lambda f: f.ts)
