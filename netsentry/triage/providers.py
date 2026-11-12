"""LLM providers behind a single tool-calling interface.

* :class:`AnthropicProvider` calls Claude via the Messages API with tool use.
* :class:`HeuristicProvider` is a deterministic, offline stand-in that speaks
  the same protocol. It exists so CI and the eval harness run without network
  or API keys, and as a baseline to compare a real model against. It is *not*
  an LLM and its eval numbers should be read as a floor.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict


@dataclass
class ModelTurn:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw: Any = None
    usage: dict = field(default_factory=dict)


class Provider:
    name = "base"

    def complete(self, system: str, messages: list[dict], tools: list[dict]) -> ModelTurn:  # pragma: no cover
        raise NotImplementedError


class AnthropicProvider(Provider):
    name = "anthropic"

    def __init__(self, model: str | None = None, max_tokens: int = 1024, temperature: float = 0.0):
        try:
            import anthropic  # type: ignore
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError("pip install 'netsentry[llm]' to use the Anthropic provider") from exc
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        self.client = anthropic.Anthropic()
        self.model = model or os.environ.get("NETSENTRY_MODEL", "claude-sonnet-5-5")
        self.max_tokens = max_tokens
        self.temperature = temperature

    def complete(self, system, messages, tools):  # pragma: no cover - network
        resp = self.client.messages.create(
            model=self.model, system=system, messages=messages, tools=tools,
            max_tokens=self.max_tokens, temperature=self.temperature,
        )
        turn = ModelTurn(raw=resp, usage={"input_tokens": resp.usage.input_tokens,
                                          "output_tokens": resp.usage.output_tokens})
        for block in resp.content:
            if block.type == "text":
                turn.text += block.text
            elif block.type == "tool_use":
                turn.tool_calls.append(ToolCall(block.id, block.name, dict(block.input)))
        return turn


class HeuristicProvider(Provider):
    """Rule-based analyst that reads only the rendered context.

    Turn 1: if no asset record is present for the alert's key host, call the
    ``get_asset`` tool (exercises the agent loop). Turn 2+: emit a decision.
    """

    name = "heuristic"

    def complete(self, system, messages, tools):
        ctx = _flatten(messages)
        alert = _alert_header(ctx)
        asked = any(m["role"] == "assistant" for m in messages)
        key_ip = alert.get("src") if alert.get("type") in ("port_scan", "beaconing") else alert.get("dst")
        if not asked and key_ip and f"{key_ip}:" not in _section(ctx, "asset"):
            return ModelTurn(tool_calls=[ToolCall("tc1", "get_asset", {"ip": key_ip})])
        return ModelTurn(text=json.dumps(self._decide(alert, ctx)))

    def _decide(self, a: dict, ctx: str) -> dict:
        t = a.get("type", "")
        m = a.get("metrics", {})
        ids = re.findall(r"\[(E\d+)\] \(detector\)", ctx)[:2] or re.findall(r"\[(E\d+)\]", ctx)[:1]
        trusted = _strip_untrusted(ctx).lower()
        benign_cues = [c for c in ("authorized", "vulnerability scanner", "load test", "product launch",
                                   "backup", "monitoring", "health check", "patch management") if c in trusted]
        cue_ids = [i for i, line in _evidence_lines(ctx)
                   if line.startswith(("(asset)", "(change_calendar)"))
                   and any(c in line.lower() for c in benign_cues)]
        techs = a.get("techniques", [])
        sev = a.get("severity", "medium")

        if benign_cues and t != "amplification":
            unexpected = "outside" in trusted or "not expected" in trusted
            if unexpected:
                return self._out("needs_review", sev, techs, "escalate",
                                 f"Benign context present ({', '.join(benign_cues)}) but activity falls outside it.",
                                 ids + cue_ids)
            return self._out("benign", "low", [], "none",
                             f"Activity matches documented benign context: {', '.join(benign_cues)}.",
                             ids + cue_ids)
        if t == "traffic_anomaly":
            if m.get("syn_ratio", 0) < 0.2 and m.get("fail_ratio", 0) < 0.2:
                return self._out("needs_review", "low", [], "escalate",
                                 "Volume spike with completed handshakes; could be legitimate demand.", ids)
            return self._out("true_positive", "medium", techs, "rate_limit",
                             "Volume spike dominated by failed/half-open connections.", ids)
        action = {"syn_flood": "rate_limit", "udp_flood": "rate_limit", "amplification": "drop_reflection",
                  "port_scan": "block_src", "beaconing": "block_dst"}.get(t, "escalate")
        if t == "port_scan" and a.get("src", "").startswith(("10.", "192.168.", "172.")):
            action = "quarantine_host"
        if a.get("confidence", 0) < 0.6:
            return self._out("needs_review", sev, techs, "escalate", "Detector confidence is low.", ids)
        return self._out("true_positive", sev, techs, action,
                         f"{t.replace('_', ' ')} indicators exceed baseline; no benign context found.", ids)

    @staticmethod
    def _out(verdict, severity, techs, action, rationale, ids):
        return {"verdict": verdict, "severity": severity,
                "techniques": [x["id"] if isinstance(x, dict) else x for x in techs],
                "recommended_action": action, "rationale": rationale,
                "evidence_ids": list(dict.fromkeys(ids)) or ["E1"]}


# --------------------------------------------------------------------- helpers

def _flatten(messages: list[dict]) -> str:
    out = []
    for m in messages:
        c = m["content"]
        if isinstance(c, str):
            out.append(c)
        else:
            for b in c:
                if b.get("type") == "text":
                    out.append(b["text"])
                elif b.get("type") == "tool_result":
                    out.append(b["content"] if isinstance(b["content"], str) else json.dumps(b["content"]))
    return "\n".join(out)


def _alert_header(ctx: str) -> dict:
    m = re.search(r"## Alert\n(\{.*?\})\n", ctx)
    if not m:
        return {}
    a = json.loads(m.group(1))
    a["techniques"] = a.get("techniques", [])
    return a


def _evidence_lines(ctx: str) -> list[tuple[str, str]]:
    return re.findall(r"^\[(E\d+)\] (.*)$", ctx, re.M)


def _section(ctx: str, kind: str) -> str:
    return "\n".join(line for _, line in _evidence_lines(ctx) if line.startswith(f"({kind})"))


def _strip_untrusted(ctx: str) -> str:
    return re.sub(r"<untrusted_data.*?</untrusted_data>", "", ctx, flags=re.S)


def get_provider(name: str, **kw) -> Provider:
    if name in ("heuristic", "mock"):
        return HeuristicProvider()
    if name in ("anthropic", "claude"):
        return AnthropicProvider(**kw)
    raise ValueError(f"unknown provider {name!r}")
