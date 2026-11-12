"""NetSentry command line.

    netsentry gen-pcaps data/pcaps
    netsentry detect data/samples/conn_beaconing.log.gz --out alerts.jsonl
    netsentry respond alerts.jsonl                 # dry run: prints nft commands
    netsentry replay data/scenarios.yaml           # validate against attack PCAPs
    netsentry triage alerts.jsonl --provider anthropic
    netsentry eval --provider heuristic
    netsentry export data/pcaps/port_scan.pcap --zeek conn.log --netflow flows.csv
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import Config


def _alerts(path: str):
    from .models import Alert

    return [Alert.from_dict(json.loads(line)) for line in Path(path).read_text().splitlines() if line.strip()]


def cmd_gen(args) -> int:
    from .replay.generate import SCENARIOS, generate

    for name in args.scenario or list(SCENARIOS):
        p = generate(name, args.out_dir, seed=args.seed)
        print(f"wrote {p} ({p.stat().st_size / 1e6:.1f} MB)")
    return 0


def cmd_detect(args) -> int:
    from .detect import run_detection
    from .ingest import load_flows

    cfg = Config.load(args.config)
    if args.window:
        cfg.window = args.window
    flows = load_flows(args.input, args.kind)
    res = run_detection(flows, cfg)
    for target in (args.out, args.baselines_out):
        if target:
            Path(target).parent.mkdir(parents=True, exist_ok=True)
    out = open(args.out, "w") if args.out else sys.stdout
    for a in res.alerts:
        out.write(a.to_json() + "\n")
    if args.out:
        out.close()
    if args.baselines_out:
        Path(args.baselines_out).write_text(json.dumps(res.baselines, indent=1, sort_keys=True))
    print(f"{res.flows} flows -> {len(res.alerts)} alerts", file=sys.stderr)
    for a in res.alerts:
        print(f"  [{a.severity:<8}] {a.type:<15} src={a.src or ','.join(a.top_sources[:2]) or '-'} "
              f"dst={a.dst or '-'}:{a.dport if a.dport is not None else '*'} "
              f"att&ck={','.join(t.id for t in a.techniques) or '-'} conf={a.confidence}", file=sys.stderr)
    return 0


def cmd_respond(args) -> int:
    from .respond import ResponseEngine

    cfg = Config.load(args.config)
    if args.apply:
        cfg.response.dry_run = False
    report = ResponseEngine(cfg, audit_log=args.audit_log).run(_alerts(args.alerts))
    for r in report["results"]:
        a = r["action"]
        tag = "APPLIED" if r.get("applied") else r.get("note", r.get("error", "skipped")).upper()
        print(f"[{tag}] {r['backend']}: {a['kind']} {a['target']}  ({a['reason']})")
        for c in r.get("commands", []):
            print(f"    {c}")
    for s in report["skipped"]:
        print(f"[SKIP] {s['type']} {s.get('target') or ''}: {s['reason']}")
    return 0


def cmd_replay(args) -> int:
    from .replay.harness import format_results, run_manifest

    results = run_manifest(args.manifest, Config.load(args.config))
    print(format_results(results))
    return 0 if all(r.passed for r in results) else 1


def cmd_triage(args) -> int:
    from .triage import TriageAgent, TriageStore, get_provider

    cfg = Config.load(args.config)
    alerts = _alerts(args.alerts)
    store = TriageStore(
        baselines=json.loads(Path(args.baselines).read_text()) if args.baselines else {},
        assets=cfg.assets, alerts=[a.to_dict() for a in alerts])
    agent = TriageAgent(get_provider(args.provider), store)
    for a in alerts:
        r = agent.triage(a)
        d = r.decision
        print(json.dumps({"alert_id": a.id, "type": a.type, **d, "valid": r.valid,
                          "tool_calls": r.tool_calls, "fell_back": r.fell_back}))
    return 0


def cmd_eval(args) -> int:
    from .evals import load_dataset, run_eval, to_markdown
    from .triage import get_provider

    rep = run_eval(load_dataset(args.dataset), get_provider(args.provider), counterfactual=not args.no_cf)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(rep, indent=1))
    print(to_markdown(rep))
    return 0


def cmd_export(args) -> int:
    from .ingest import load_flows
    from .ingest.export import write_netflow_csv, write_zeek_conn

    flows = load_flows(args.input)
    if args.zeek:
        print(f"zeek conn.log: {write_zeek_conn(flows, args.zeek)} rows -> {args.zeek}")
    if args.netflow:
        print(f"netflow csv: {write_netflow_csv(flows, args.netflow)} rows -> {args.netflow}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="netsentry", description="Infrastructure anomaly & DDoS detection")
    p.add_argument("--config", help="YAML config (see config/netsentry.yaml)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("gen-pcaps", help="synthesise labelled attack PCAPs")
    s.add_argument("out_dir")
    s.add_argument("--scenario", action="append")
    s.add_argument("--seed", type=int, default=7)
    s.set_defaults(fn=cmd_gen)

    s = sub.add_parser("detect", help="run detectors over Zeek / NetFlow / PCAP")
    s.add_argument("input")
    s.add_argument("--kind", default="auto", choices=["auto", "zeek", "netflow", "pcap"])
    s.add_argument("--window", type=float)
    s.add_argument("--out")
    s.add_argument("--baselines-out")
    s.set_defaults(fn=cmd_detect)

    s = sub.add_parser("respond", help="plan and (optionally) enforce mitigations")
    s.add_argument("alerts")
    s.add_argument("--apply", action="store_true", help="actually enforce (default: dry run)")
    s.add_argument("--audit-log", default="state/audit.jsonl")
    s.set_defaults(fn=cmd_respond)

    s = sub.add_parser("replay", help="validate detection+response against labelled PCAPs")
    s.add_argument("manifest")
    s.set_defaults(fn=cmd_replay)

    s = sub.add_parser("triage", help="LLM triage of alerts")
    s.add_argument("alerts")
    s.add_argument("--baselines")
    s.add_argument("--provider", default="heuristic", choices=["heuristic", "anthropic"])
    s.set_defaults(fn=cmd_triage)

    s = sub.add_parser("eval", help="evaluate triage accuracy, hallucination and bias")
    s.add_argument("--dataset", default="evals/dataset.jsonl")
    s.add_argument("--provider", default="heuristic", choices=["heuristic", "anthropic"])
    s.add_argument("--out")
    s.add_argument("--no-cf", action="store_true", help="skip counterfactual bias runs")
    s.set_defaults(fn=cmd_eval)

    s = sub.add_parser("export", help="convert telemetry to Zeek conn.log / NetFlow CSV")
    s.add_argument("input")
    s.add_argument("--zeek")
    s.add_argument("--netflow")
    s.set_defaults(fn=cmd_export)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
