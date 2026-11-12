"""Evaluation harness for LLM triage: accuracy, hallucination and bias.

Metrics
-------
accuracy        verdict accuracy and macro-F1 over {true_positive, benign, needs_review};
                action accuracy (gold lists acceptable actions); technique precision/recall.
hallucination   share of cases whose *first* model answer cited non-existent evidence,
                named an unknown ATT&CK technique, or mentioned an IP not in context;
                plus the share still hallucinating after the repair loop, and fallbacks.
bias            per-slice (source region, ASN type) accuracy and false-positive rate with
                the max gap between groups, and a counterfactual test: re-run each case
                with only the source's country/ASN swapped and count verdict flips.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from .triage import TriageAgent, TriageStore
from .triage.providers import Provider

VERDICTS = ["true_positive", "benign", "needs_review"]
SWAP = {"US": ("BR", "AS28573 Claro", "residential"), "BR": ("US", "AS7922 Comcast", "residential"),
        "NG": ("US", "AS16509 Amazon", "cloud")}


def load_dataset(path: str | Path) -> list[dict]:
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def _store(case: dict) -> TriageStore:
    s = case["store"]
    return TriageStore(baselines=s.get("baselines", {}), assets=s.get("assets", {}),
                       alerts=s.get("alerts", []), enrichment=s.get("enrichment", {}),
                       change_calendar=s.get("change_calendar", []), untrusted=s.get("untrusted", {}))


def _counterfactual(case: dict) -> dict | None:
    ip = case.get("counterfactual_ip")
    enr = case["store"].get("enrichment", {}).get(ip) if ip else None
    if not enr or enr["country"] not in SWAP:
        return None
    c = json.loads(json.dumps(case))
    country, asn, asn_type = SWAP[enr["country"]]
    c["store"]["enrichment"][ip] = {"country": country, "asn": asn, "asn_type": asn_type}
    return c


def _f1(golds: list[str], preds: list[str]) -> float:
    f1s = []
    for v in VERDICTS:
        tp = sum(g == v and p == v for g, p in zip(golds, preds))
        fp = sum(g != v and p == v for g, p in zip(golds, preds))
        fn = sum(g == v and p != v for g, p in zip(golds, preds))
        if tp + fp + fn == 0:
            continue
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1s.append(2 * prec * rec / (prec + rec) if prec + rec else 0.0)
    return sum(f1s) / len(f1s) if f1s else 0.0


def run_eval(dataset: list[dict], provider: Provider, counterfactual: bool = True) -> dict:
    rows = []
    for case in dataset:
        res = TriageAgent(provider, _store(case)).triage(case["alert"])
        d, gold = res.decision, case["gold"]
        pred_t = set(d.get("techniques", []))
        gold_t = set(gold["techniques"])
        row = {
            "id": case["id"], "scenario": case["scenario"], "slice": case.get("slice", {}),
            "gold_verdict": gold["verdict"], "pred_verdict": d.get("verdict"),
            "verdict_ok": d.get("verdict") == gold["verdict"],
            "action_ok": d.get("recommended_action") in gold["actions"],
            "tech_tp": len(pred_t & gold_t), "tech_pred": len(pred_t), "tech_gold": len(gold_t),
            "halluc_first": bool(res.first_attempt_hallucinations),
            "halluc_final": bool(res.final_hallucinations),
            "halluc_detail": res.first_attempt_hallucinations,
            "repaired": res.repaired, "fell_back": res.fell_back, "tool_calls": len(res.tool_calls),
            "latency_s": res.latency_s, "rationale": d.get("rationale", ""),
        }
        if counterfactual:
            cf = _counterfactual(case)
            if cf is not None:
                cf_res = TriageAgent(provider, _store(cf)).triage(cf["alert"])
                row["cf_flip"] = cf_res.decision.get("verdict") != d.get("verdict")
        rows.append(row)
    return summarize(rows, provider.name)


def summarize(rows: list[dict], provider_name: str) -> dict:
    n = len(rows)
    tech_rows = [r for r in rows if r["tech_gold"]]
    tp = sum(r["tech_tp"] for r in tech_rows)
    report = {
        "provider": provider_name,
        "cases": n,
        "accuracy": {
            "verdict_accuracy": round(sum(r["verdict_ok"] for r in rows) / n, 4),
            "verdict_macro_f1": round(_f1([r["gold_verdict"] for r in rows], [r["pred_verdict"] for r in rows]), 4),
            "action_accuracy": round(sum(r["action_ok"] for r in rows) / n, 4),
            "technique_precision": round(tp / max(1, sum(r["tech_pred"] for r in tech_rows)), 4),
            "technique_recall": round(tp / max(1, sum(r["tech_gold"] for r in tech_rows)), 4),
        },
        "hallucination": {
            "first_attempt_rate": round(sum(r["halluc_first"] for r in rows) / n, 4),
            "final_rate": round(sum(r["halluc_final"] for r in rows) / n, 4),
            "repair_rate": round(sum(r["repaired"] for r in rows) / n, 4),
            "fallback_rate": round(sum(r["fell_back"] for r in rows) / n, 4),
        },
        "bias": {},
        "ops": {
            "avg_tool_calls": round(sum(r["tool_calls"] for r in rows) / n, 2),
            "avg_latency_s": round(sum(r["latency_s"] for r in rows) / n, 4),
        },
        "rows": rows,
    }
    for key in ("region", "asn_type"):
        groups: dict[str, list[dict]] = defaultdict(list)
        for r in rows:
            if key in r["slice"]:
                groups[r["slice"][key]].append(r)
        per = {}
        for g, rs in sorted(groups.items()):
            neg = [r for r in rs if r["gold_verdict"] != "true_positive"]
            per[g] = {"n": len(rs), "accuracy": round(sum(r["verdict_ok"] for r in rs) / len(rs), 4),
                      "false_positive_rate": round(sum(r["pred_verdict"] == "true_positive" for r in neg)
                                                   / len(neg), 4) if neg else None}
        accs = [v["accuracy"] for v in per.values()]
        fprs = [v["false_positive_rate"] for v in per.values() if v["false_positive_rate"] is not None]
        report["bias"][key] = {"groups": per,
                               "accuracy_gap": round(max(accs) - min(accs), 4) if accs else 0.0,
                               "fpr_gap": round(max(fprs) - min(fprs), 4) if fprs else 0.0}
    cf = [r for r in rows if "cf_flip" in r]
    report["bias"]["counterfactual"] = {"pairs": len(cf),
                                        "flip_rate": round(sum(r["cf_flip"] for r in cf) / len(cf), 4) if cf else None}
    return report


def to_markdown(rep: dict) -> str:
    a, h, b = rep["accuracy"], rep["hallucination"], rep["bias"]
    lines = [f"### Triage eval: `{rep['provider']}` ({rep['cases']} cases)", "",
             "| metric | value |", "|---|---|"]
    for k, v in {**a, **{f"hallucination_{k}": v for k, v in h.items()}}.items():
        lines.append(f"| {k} | {v} |")
    for key in ("region", "asn_type"):
        lines.append(f"| bias: {key} accuracy gap | {b[key]['accuracy_gap']} |")
        lines.append(f"| bias: {key} FPR gap | {b[key]['fpr_gap']} |")
    lines.append(f"| bias: counterfactual flip rate | {b['counterfactual']['flip_rate']} "
                 f"({b['counterfactual']['pairs']} pairs) |")
    misses = [r for r in rep["rows"] if not r["verdict_ok"]]
    if misses:
        lines += ["", "Misclassified:", ""]
        for r in misses:
            lines.append(f"- `{r['id']}`: gold `{r['gold_verdict']}`, predicted `{r['pred_verdict']}`")
    return "\n".join(lines)
