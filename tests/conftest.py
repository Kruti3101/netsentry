from __future__ import annotations

import random

import pytest

from netsentry.config import Config
from netsentry.models import FlowRecord

T0 = 1_700_000_000.0


def web_session(ts: float, src: str, dst: str = "10.0.0.10", dport: int = 443) -> FlowRecord:
    return FlowRecord(ts=ts, src=src, sport=random.randint(32768, 60999), dst=dst, dport=dport, proto="tcp",
                      duration=0.2, orig_bytes=400, resp_bytes=1400, orig_pkts=4, resp_pkts=3,
                      conn_state="SF", tcp_flags="SAF", source="test")


def syn(ts: float, src: str, dst: str = "10.0.0.10", dport: int = 443, state: str = "S0") -> FlowRecord:
    return FlowRecord(ts=ts, src=src, sport=random.randint(1024, 65535), dst=dst, dport=dport, proto="tcp",
                      orig_pkts=1, conn_state=state, tcp_flags="S", source="test")


@pytest.fixture
def cfg() -> Config:
    return Config()


@pytest.fixture
def background() -> list[FlowRecord]:
    """10 minutes of steady web traffic (~3 sessions/s)."""
    rng = random.Random(1)
    flows, t = [], T0
    while t < T0 + 600:
        t += rng.expovariate(3.0)
        flows.append(web_session(t, f"198.51.100.{rng.randint(1, 254)}"))
    return flows
