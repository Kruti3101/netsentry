import random

from conftest import T0, syn, web_session

from netsentry.detect import run_detection
from netsentry.detect.baseline import EWMA, ServiceBaseline
from netsentry.models import FlowRecord


def test_ewma_converges():
    e = EWMA(alpha=0.1)
    for _ in range(200):
        e.update(10.0)
    assert abs(e.mean - 10.0) < 1e-6 and e.var < 1e-6


def test_baseline_not_poisoned_by_attack():
    sb = ServiceBaseline(["x"], alpha=0.2, warmup=5, rel_floor=0.1, max_freeze=3)
    for _ in range(20):
        sb.observe({"x": 10.0}, anomalous=False)
    mean_before = sb.models["x"].mean
    sb.observe({"x": 10_000.0}, anomalous=True)
    assert sb.models["x"].mean == mean_before          # frozen during the attack
    for _ in range(5):                                    # sustained shift -> resumes learning
        sb.observe({"x": 10_000.0}, anomalous=True)
    assert sb.models["x"].mean > mean_before


def test_syn_flood_detected_with_attack_mapping(background, cfg):
    rng = random.Random(2)
    attack = [syn(T0 + 400 + i / 500, f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.0.{rng.randint(1, 254)}")
              for i in range(500 * 30)]
    res = run_detection(background + attack, cfg)
    floods = [a for a in res.alerts if a.type == "syn_flood"]
    assert len(floods) == 1
    a = floods[0]
    assert a.dst == "10.0.0.10" and a.dport == 443
    assert {"T1499.001"} <= {t.id for t in a.techniques}
    assert T0 + 390 <= a.ts_start <= T0 + 410 and a.severity in ("high", "critical")
    assert a.top_sources == []            # spoofed: no source carries >=1% of packets


def test_flash_crowd_is_not_a_syn_flood(background, cfg):
    rng = random.Random(3)
    crowd = [web_session(T0 + 400 + i / 40, f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.1.1")
             for i in range(40 * 30)]
    res = run_detection(background + crowd, cfg)
    types = {a.type for a in res.alerts}
    assert "syn_flood" not in types
    assert types <= {"traffic_anomaly"}


def test_no_alerts_on_clean_background(background, cfg):
    assert run_detection(background, cfg).alerts == []


def test_vertical_and_horizontal_scans(cfg):
    flows = [syn(T0 + i * 0.02, "203.0.113.66", dport=p, state="REJ") for i, p in enumerate(range(1, 200))]
    flows += [syn(T0 + 100 + i * 0.1, "10.0.1.50", dst=f"10.0.2.{i}", dport=22) for i in range(1, 100)]
    alerts = [a for a in run_detection(flows, cfg).alerts if a.type == "port_scan"]
    by_src = {a.src: a for a in alerts}
    assert set(by_src) == {"203.0.113.66", "10.0.1.50"}
    assert "T1595.001" in {t.id for t in by_src["203.0.113.66"].techniques}       # external recon
    assert "T1595.001" not in {t.id for t in by_src["10.0.1.50"].techniques}
    assert by_src["10.0.1.50"].dport == 22


def _conn(ts, dst="203.0.113.200", src="10.0.1.23", size=320):
    return FlowRecord(ts=ts, src=src, sport=50000, dst=dst, dport=443, proto="tcp", orig_bytes=size,
                      orig_pkts=4, resp_pkts=3, conn_state="SF")


def test_beacon_detected_with_jitter_and_a_missed_checkin(cfg):
    rng = random.Random(4)
    ts, t = [], T0
    for _ in range(20):
        ts.append(t)
        t += 60 * (1 + rng.uniform(-0.05, 0.05))
    del ts[7]                                            # missed check-in -> one 120s gap
    (a,) = run_detection([_conn(t) for t in ts], cfg).alerts
    assert a.type == "beaconing" and a.dst == "203.0.113.200"
    assert {"T1071.001", "T1573"} <= {t.id for t in a.techniques}


def test_irregular_browsing_is_not_a_beacon(cfg):
    rng = random.Random(5)
    t, flows = T0, []
    for _ in range(30):
        t += rng.expovariate(1 / 60)
        flows.append(_conn(t, size=rng.randint(200, 3000)))
    assert run_detection(flows, cfg).alerts == []


def test_internal_to_internal_periodic_is_ignored(cfg):
    flows = [_conn(T0 + i * 60, dst="10.0.0.99") for i in range(20)]
    assert run_detection(flows, cfg).alerts == []
