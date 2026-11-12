"""Synthesise labelled attack PCAPs on top of realistic background traffic.

Every scenario shares the same seeded background (web clients, DNS, internal
browsing) so baselines warm up identically; the attack is injected at
``ATTACK_START``. Addresses use RFC 5737 documentation ranges for "internet"
hosts and 10.0.0.0/8 for the protected network.
"""
from __future__ import annotations

import random
from pathlib import Path

from .pcap import TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, PcapWriter

T0 = 1_700_000_000.0
DURATION = 900.0           # 15 minutes of capture
ATTACK_START = T0 + 600.0  # attack begins after 10 minutes of baseline
ATTACK_LEN = 60.0

WEB = "10.0.0.10"
DNS = "10.0.0.53"
INTERNAL_CLIENTS = [f"10.0.1.{i}" for i in range(10, 60)]
EXTERNAL_CLIENTS = [f"198.51.100.{i}" for i in range(1, 255)] + [f"203.0.113.{i}" for i in range(1, 60)]
EXTERNAL_SITES = ["192.0.2.80", "192.0.2.81", "192.0.2.82", "192.0.2.90"]
C2 = "203.0.113.200"
BEACON_HOST = "10.0.1.23"
SCANNER_EXT = "203.0.113.66"
SCANNER_INT = "10.0.1.50"
REFLECTORS = [f"198.51.100.{i}" for i in range(100, 200)]


class _Events:
    """Collect (ts, fn, args) and write them in timestamp order."""

    def __init__(self):
        self.ev: list[tuple[float, str, tuple]] = []

    def tcp(self, ts, *args, **kw):
        self.ev.append((ts, "tcp", args, kw))

    def udp(self, ts, *args, **kw):
        self.ev.append((ts, "udp", args, kw))

    def write(self, path: Path) -> int:
        self.ev.sort(key=lambda e: e[0])
        with PcapWriter(path) as w:
            for ts, kind, args, kw in self.ev:
                getattr(w, kind)(ts, *args, **kw)
            return w.count


def _tcp_session(ev: _Events, rng: random.Random, ts: float, c: str, s: str, dport: int,
                 req: int = 400, resp: int = 1400) -> None:
    sp = rng.randint(32768, 60999)
    rtt = rng.uniform(0.01, 0.06)
    ev.tcp(ts, c, sp, s, dport, TCP_SYN)
    ev.tcp(ts + rtt, s, dport, c, sp, TCP_SYN | TCP_ACK)
    ev.tcp(ts + 2 * rtt, c, sp, s, dport, TCP_ACK)
    ev.tcp(ts + 2 * rtt + 0.001, c, sp, s, dport, TCP_PSH | TCP_ACK, payload=req)
    ev.tcp(ts + 3 * rtt, s, dport, c, sp, TCP_PSH | TCP_ACK, payload=resp)
    ev.tcp(ts + 3 * rtt + 0.002, c, sp, s, dport, TCP_FIN | TCP_ACK)
    ev.tcp(ts + 4 * rtt, s, dport, c, sp, TCP_FIN | TCP_ACK)


def _poisson(rng: random.Random, rate: float, start: float, end: float):
    t = start
    while True:
        t += rng.expovariate(rate)
        if t >= end:
            return
        yield t


def background(ev: _Events, seed: int = 7, web_rate: float = 3.0) -> None:
    rng = random.Random(seed)
    end = T0 + DURATION
    # inbound web traffic with a mild diurnal-style wobble
    for t in _poisson(rng, web_rate, T0, end):
        if rng.random() < 0.85 + 0.15 * ((t - T0) % 300) / 300:
            _tcp_session(ev, rng, t, rng.choice(EXTERNAL_CLIENTS), WEB, 443,
                         req=rng.randint(200, 900), resp=rng.randint(800, 1460))
    # internal DNS
    for t in _poisson(rng, 2.0, T0, end):
        c = rng.choice(INTERNAL_CLIENTS)
        sp = rng.randint(1024, 65535)
        ev.udp(t, c, sp, DNS, 53, payload=rng.randint(30, 60))
        ev.udp(t + rng.uniform(0.001, 0.01), DNS, 53, c, sp, payload=rng.randint(60, 300))
    # internal users browsing the internet (irregular, should NOT look like beacons)
    for t in _poisson(rng, 0.5, T0, end):
        _tcp_session(ev, rng, t, rng.choice(INTERNAL_CLIENTS), rng.choice(EXTERNAL_SITES), 443,
                     req=rng.randint(300, 2000), resp=rng.randint(1000, 1460))


def syn_flood(ev: _Events, rng: random.Random, pps: int = 800) -> None:
    n = int(pps * ATTACK_LEN)
    for i in range(n):
        t = ATTACK_START + i / pps + rng.uniform(0, 1 / pps)
        src = f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        ev.tcp(t, src, rng.randint(1024, 65535), WEB, 443, TCP_SYN, seq=rng.getrandbits(32))


def udp_flood(ev: _Events, rng: random.Random, pps: int = 1500) -> None:
    bots = [f"198.51.100.{i}" for i in range(201, 209)]
    for i in range(int(pps * ATTACK_LEN)):
        t = ATTACK_START + i / pps
        ev.udp(t, rng.choice(bots), rng.randint(1024, 65535), DNS, 53, payload=512)


def amplification(ev: _Events, rng: random.Random, pps: int = 1500) -> None:
    for i in range(int(pps * ATTACK_LEN)):
        t = ATTACK_START + i / pps
        ev.udp(t, rng.choice(REFLECTORS), 123, WEB, rng.randint(1024, 65535), payload=468)


def port_scan(ev: _Events, rng: random.Random) -> None:
    # external vertical scan of the web server: 1-1024 over 30s
    for i, port in enumerate(range(1, 1025)):
        t = ATTACK_START + i * (30 / 1024)
        sp = rng.randint(40000, 60000)
        ev.tcp(t, SCANNER_EXT, sp, WEB, port, TCP_SYN)
        if port == 443:
            ev.tcp(t + 0.01, WEB, port, SCANNER_EXT, sp, TCP_SYN | TCP_ACK)
            ev.tcp(t + 0.02, SCANNER_EXT, sp, WEB, port, TCP_RST)
        else:
            ev.tcp(t + 0.01, WEB, port, SCANNER_EXT, sp, TCP_RST | TCP_ACK)
    # internal horizontal SSH sweep (lateral-movement recon)
    for i in range(1, 255):
        t = ATTACK_START + 120 + i * 0.1
        ev.tcp(t, SCANNER_INT, rng.randint(40000, 60000), f"10.0.2.{i}", 22, TCP_SYN)


def beacon(ev: _Events, rng: random.Random, interval: float = 60.0, jitter: float = 0.05) -> None:
    t = T0 + rng.uniform(0, interval)
    while t < T0 + DURATION:
        _tcp_session(ev, rng, t, BEACON_HOST, C2, 443, req=rng.randint(310, 330), resp=rng.randint(90, 110))
        t += interval * (1 + rng.uniform(-jitter, jitter))


def flash_crowd(ev: _Events, rng: random.Random, rate: float = 40.0) -> None:
    """Benign: a product launch sends a legitimate surge of complete sessions."""
    for t in _poisson(rng, rate, ATTACK_START, ATTACK_START + ATTACK_LEN):
        c = f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        _tcp_session(ev, rng, t, c, WEB, 443)


SCENARIOS = {
    "baseline": None,
    "syn_flood": syn_flood,
    "udp_flood": udp_flood,
    "amplification": amplification,
    "port_scan": port_scan,
    "beaconing": beacon,
    "flash_crowd": flash_crowd,
}


def generate(name: str, out_dir: str | Path, seed: int = 7) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ev = _Events()
    background(ev, seed)
    fn = SCENARIOS[name]
    if fn:
        fn(ev, random.Random(seed + 1000))
    path = out_dir / f"{name}.pcap"
    ev.write(path)
    return path


def generate_all(out_dir: str | Path, seed: int = 7) -> list[Path]:
    return [generate(n, out_dir, seed) for n in SCENARIOS]
