"""Minimal dependency-free libpcap reader/writer.

Supports classic pcap (micro/nanosecond, either byte order) with Ethernet
(incl. 802.1Q), Linux cooked (SLL) and raw-IP link types; IPv4 TCP/UDP/ICMP.
That covers the common public attack captures. pcapng is not supported:
convert with ``editcap -F pcap in.pcapng out.pcap``.
"""
from __future__ import annotations

import socket
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10


@dataclass(slots=True)
class Packet:
    ts: float
    src: str
    dst: str
    proto: str          # tcp | udp | icmp
    sport: int
    dport: int
    flags: int          # TCP flag bits, 0 otherwise
    length: int         # IP total length
    payload_len: int


def read_pcap(path: str | Path) -> Iterator[Packet]:
    with open(path, "rb") as fh:
        yield from _read(fh)


def _read(fh: BinaryIO) -> Iterator[Packet]:
    hdr = fh.read(24)
    if len(hdr) < 24:
        return
    magic = hdr[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, ts_div = "<", 1e6
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, ts_div = ">", 1e6
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, ts_div = "<", 1e9
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, ts_div = ">", 1e9
    elif magic == b"\x0a\x0d\x0d\x0a":
        raise ValueError("pcapng not supported; convert with: editcap -F pcap in.pcapng out.pcap")
    else:
        raise ValueError("not a pcap file")
    linktype = struct.unpack(endian + "I", hdr[20:24])[0]
    rec = struct.Struct(endian + "IIII")
    while True:
        rh = fh.read(16)
        if len(rh) < 16:
            return
        sec, frac, incl, _orig = rec.unpack(rh)
        data = fh.read(incl)
        if len(data) < incl:
            return
        pkt = _decode(data, linktype, sec + frac / ts_div)
        if pkt is not None:
            yield pkt


def _decode(data: bytes, linktype: int, ts: float) -> Packet | None:
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        etype = struct.unpack("!H", data[12:14])[0]
        off = 14
        while etype in (0x8100, 0x88A8) and len(data) >= off + 4:
            etype = struct.unpack("!H", data[off + 2:off + 4])[0]
            off += 4
        if etype != 0x0800:
            return None
        ip = data[off:]
    elif linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16 or struct.unpack("!H", data[14:16])[0] != 0x0800:
            return None
        ip = data[16:]
    elif linktype == LINKTYPE_RAW:
        ip = data
    else:
        return None
    return _decode_ipv4(ip, ts)


def _decode_ipv4(ip: bytes, ts: float) -> Packet | None:
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    total = struct.unpack("!H", ip[2:4])[0]
    proto_num = ip[9]
    src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
    l4 = ip[ihl:]
    if proto_num == 6 and len(l4) >= 14:
        sport, dport = struct.unpack("!HH", l4[:4])
        doff = (l4[12] >> 4) * 4
        return Packet(ts, src, dst, "tcp", sport, dport, l4[13], total, max(total - ihl - doff, 0))
    if proto_num == 17 and len(l4) >= 8:
        sport, dport = struct.unpack("!HH", l4[:4])
        return Packet(ts, src, dst, "udp", sport, dport, 0, total, max(total - ihl - 8, 0))
    if proto_num == 1:
        return Packet(ts, src, dst, "icmp", 0, 0, 0, total, max(total - ihl - 8, 0))
    return None


# --------------------------------------------------------------------------- writer

def _checksum(b: bytes) -> int:
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b) // 2}H", b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


class PcapWriter:
    """Writes Ethernet/IPv4 packets. Used to synthesise attack captures."""

    def __init__(self, path: str | Path):
        self.fh = open(path, "wb")
        self.fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        self.count = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self) -> None:
        self.fh.close()

    def _ip(self, src: str, dst: str, proto: int, l4: bytes, ttl: int = 64) -> bytes:
        hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), self.count & 0xFFFF, 0, ttl, proto, 0,
                          socket.inet_aton(src), socket.inet_aton(dst))
        hdr = hdr[:10] + struct.pack("!H", _checksum(hdr)) + hdr[12:]
        return hdr + l4

    def tcp(self, ts: float, src: str, sport: int, dst: str, dport: int, flags: int,
            payload: int = 0, seq: int = 0, ack: int = 0) -> None:
        l4 = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0) + b"\0" * payload
        self._write(ts, self._ip(src, dst, 6, l4))

    def udp(self, ts: float, src: str, sport: int, dst: str, dport: int, payload: int = 0) -> None:
        l4 = struct.pack("!HHHH", sport, dport, 8 + payload, 0) + b"\0" * payload
        self._write(ts, self._ip(src, dst, 17, l4))

    def _write(self, ts: float, ip: bytes) -> None:
        frame = b"\x02\0\0\0\0\x02" + b"\x02\0\0\0\0\x01" + b"\x08\x00" + ip
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        if usec >= 1_000_000:
            sec, usec = sec + 1, usec - 1_000_000
        self.fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame)
        self.count += 1
