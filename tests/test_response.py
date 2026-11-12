import json

from netsentry.config import Config
from netsentry.models import Alert
from netsentry.respond import BlocklistFileBackend, NftablesBackend, ResponseEngine, plan_response


def _alert(**kw):
    base = dict(type="port_scan", severity="high", ts_start=0, ts_end=60, src="203.0.113.66", confidence=0.9)
    base.update(kw)
    return Alert(**base)


def test_scan_blocks_external_source():
    (a,) = plan_response([_alert()], Config()).actions
    assert a.kind == "block_src" and a.target == "203.0.113.66" and not a.requires_approval


def test_internal_host_requires_approval():
    (a,) = plan_response([_alert(src="10.0.1.50")], Config()).actions
    assert a.requires_approval


def test_allowlist_and_low_confidence_are_skipped():
    cfg = Config()
    cfg.response.allowlist = ["203.0.113.0/24"]
    plan = plan_response([_alert(), _alert(src="198.51.100.9", confidence=0.3)], cfg)
    assert plan.actions == []
    reasons = {s["reason"].split(" ")[0] for s in plan.skipped}
    assert reasons == {"allowlisted", "confidence"}


def test_flood_rate_limits_victim_and_never_blocks_it():
    a = _alert(type="syn_flood", src="", dst="10.0.0.10", dport=443, proto="tcp",
               top_sources=["10.0.0.10"], metrics={"top_source_share": 0.9})
    plan = plan_response([a], Config())
    assert [x.kind for x in plan.actions] == ["rate_limit"]
    assert any("victim" in s["reason"] for s in plan.skipped)


def test_spoofed_flood_does_not_block_sources():
    a = _alert(type="syn_flood", src="", dst="10.0.0.10", dport=443, top_sources=["1.2.3.4"],
               metrics={"top_source_share": 0.001})
    assert [x.kind for x in plan_response([a], Config()).actions] == ["rate_limit"]


def test_nft_rendering():
    nft = NftablesBackend()
    a = _alert(type="syn_flood", src="", dst="10.0.0.10", dport=443, proto="tcp")
    (rl,) = plan_response([a], Config()).actions
    (cmd,) = nft.render(rl)
    assert "tcp dport 443" in cmd and "limit rate over 200/second" in cmd
    (blk,) = plan_response([_alert()], Config()).actions
    assert nft.render(blk) == ["add element inet netsentry block_src { 203.0.113.66 timeout 3600s }"]
    out = nft.apply(blk)
    assert out["applied"] is False and out["note"] == "dry run"


def test_blocklist_file_ttl(tmp_path):
    now = [1000.0]
    be = BlocklistFileBackend(tmp_path / "bl.json", dry_run=False, now=lambda: now[0])
    (blk,) = plan_response([_alert()], Config()).actions
    assert be.apply(blk)["applied"]
    assert "203.0.113.66" in be.load()
    assert (tmp_path / "bl.txt").read_text().strip() == "203.0.113.66"
    now[0] += 4000
    assert be.load() == {}


def test_engine_audit_log(tmp_path):
    cfg = Config()
    log = tmp_path / "audit.jsonl"
    rep = ResponseEngine(cfg, backends=[NftablesBackend()], audit_log=log).run([_alert()])
    assert rep["dry_run"] and len(rep["results"]) == 1
    assert json.loads(log.read_text())["actions"][0]["target"] == "203.0.113.66"
