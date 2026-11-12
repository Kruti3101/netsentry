import pytest

from netsentry.config import Config
from netsentry.replay.flows import pcap_to_flows
from netsentry.replay.generate import generate
from netsentry.replay.harness import run_scenario
from netsentry.replay.pcap import TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, PcapWriter, read_pcap


def test_pcap_roundtrip_and_conn_states(tmp_path):
    p = tmp_path / "t.pcap"
    with PcapWriter(p) as w:
        # completed session -> SF
        w.tcp(1.0, "10.0.0.1", 5000, "10.0.0.2", 80, TCP_SYN)
        w.tcp(1.1, "10.0.0.2", 80, "10.0.0.1", 5000, TCP_SYN | TCP_ACK)
        w.tcp(1.2, "10.0.0.1", 5000, "10.0.0.2", 80, TCP_ACK, payload=100)
        w.tcp(1.3, "10.0.0.1", 5000, "10.0.0.2", 80, TCP_FIN | TCP_ACK)
        # rejected -> REJ
        w.tcp(2.0, "10.0.0.1", 5001, "10.0.0.2", 81, TCP_SYN)
        w.tcp(2.1, "10.0.0.2", 81, "10.0.0.1", 5001, TCP_RST | TCP_ACK)
        # unanswered -> S0
        w.tcp(3.0, "10.0.0.1", 5002, "10.0.0.2", 82, TCP_SYN)
        w.udp(4.0, "10.0.0.1", 5353, "10.0.0.2", 53, payload=40)
    pkts = list(read_pcap(p))
    assert len(pkts) == 8 and pkts[2].payload_len == 100 and pkts[-1].proto == "udp"
    states = {f.dport: f.conn_state for f in pcap_to_flows(p)}
    assert states == {80: "SF", 81: "REJ", 82: "S0", 53: "S0"}


def test_rejects_pcapng(tmp_path):
    p = tmp_path / "x.pcapng"
    p.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\0" * 40)
    with pytest.raises(ValueError, match="pcapng"):
        list(read_pcap(p))


@pytest.mark.parametrize("scenario,spec", [
    ("syn_flood", {"attack_start": 1700000600,
                   "expect": [{"type": "syn_flood", "dst": "10.0.0.10", "technique": "T1499.001"}],
                   "expect_actions": [{"kind": "rate_limit", "dst": "10.0.0.10"}],
                   "never_block": ["10.0.0.10"]}),
    ("beaconing", {"expect": [{"type": "beaconing", "dst": "203.0.113.200"}],
                   "expect_actions": [{"kind": "block_dst", "target": "203.0.113.200"}]}),
    ("flash_crowd", {"expect_not": [{"type": "syn_flood"}], "never_block": ["10.0.0.10"]}),
    ("baseline", {"max_alerts": 0}),
])
def test_replay_scenarios(tmp_path, scenario, spec):
    generate(scenario, tmp_path)
    r = run_scenario(scenario, {"pcap": f"{scenario}.pcap", **spec}, Config(), tmp_path)
    assert r.passed, [c for c in r.checks if not c[1]]
    if "attack_start" in spec:
        assert r.ttd_seconds is not None and r.ttd_seconds <= 20
