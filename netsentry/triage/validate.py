"""Output validation and grounding checks for triage decisions.

A decision is *hallucinated* if it cites evidence IDs that do not exist,
names ATT&CK techniques outside the catalog, or mentions IP addresses that
appear nowhere in the context it was given.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from ..attack import CATALOG
from .context import ACTIONS, IP_RE, VERDICTS, TriageContext

SEVERITIES = ["low", "medium", "high", "critical"]


@dataclass
class Validation:
    ok: bool
    errors: list[str] = field(default_factory=list)
    hallucinations: list[str] = field(default_factory=list)
    decision: dict | None = None


def extract_json(text: str) -> dict | None:
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fence:
        text = fence.group(1)
    else:
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end == -1:
            return None
        text = text[start:end + 1]
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def validate_decision(raw: str | dict, ctx: TriageContext) -> Validation:
    d = raw if isinstance(raw, dict) else extract_json(raw)
    if d is None:
        return Validation(False, ["output is not a JSON object"])
    errors: list[str] = []
    hallucinations: list[str] = []

    if d.get("verdict") not in VERDICTS:
        errors.append(f"verdict must be one of {VERDICTS}")
    if d.get("severity") not in SEVERITIES:
        errors.append(f"severity must be one of {SEVERITIES}")
    if d.get("recommended_action") not in ACTIONS:
        errors.append(f"recommended_action must be one of {ACTIONS}")
    if not isinstance(d.get("rationale"), str) or not d.get("rationale", "").strip():
        errors.append("rationale must be a non-empty string")

    techs = d.get("techniques", [])
    if not isinstance(techs, list):
        errors.append("techniques must be a list")
        techs = []
    for t in techs:
        if t not in CATALOG:
            hallucinations.append(f"unknown ATT&CK technique {t!r}")

    cites = d.get("evidence_ids", [])
    if not isinstance(cites, list) or not cites:
        errors.append("evidence_ids must cite at least one evidence item")
        cites = []
    for c in cites:
        if c not in ctx.ids:
            hallucinations.append(f"cited non-existent evidence {c!r}")

    known = ctx.known_entities()
    for ip in set(IP_RE.findall(str(d.get("rationale", "")))):
        if ip not in known:
            hallucinations.append(f"rationale mentions IP {ip} not present in context")

    ok = not errors and not hallucinations
    return Validation(ok, errors, hallucinations, d)
