"""Automated response: plan actions from alerts, enforce through backends, audit everything."""
from __future__ import annotations

import json
import time
from pathlib import Path

from ..config import Config
from ..models import Alert
from .backends import BlocklistFileBackend, NftablesBackend
from .policy import Action, Plan, plan_response


class ResponseEngine:
    def __init__(self, cfg: Config, backends: list | None = None, audit_log: str | Path | None = None):
        rc = cfg.response
        self.cfg = cfg
        self.backends = backends if backends is not None else [
            NftablesBackend(rc.nft_table, dry_run=rc.dry_run),
            BlocklistFileBackend(rc.blocklist_path, dry_run=rc.dry_run),
        ]
        self.audit_log = Path(audit_log) if audit_log else None

    def run(self, alerts: list[Alert]) -> dict:
        plan = plan_response(alerts, self.cfg)
        results = []
        for action in plan.actions:
            for be in self.backends:
                try:
                    out = be.apply(action)
                except Exception as exc:  # enforcement must never crash the pipeline
                    out = {"backend": getattr(be, "name", "?"), "applied": False, "error": str(exc)}
                if out.get("note") == "not a block action":
                    continue  # backend doesn't handle this action type
                results.append({"action": action.to_dict(), **out})
        report = {"ts": time.time(), "dry_run": self.cfg.response.dry_run,
                  "actions": [a.to_dict() for a in plan.actions], "skipped": plan.skipped, "results": results}
        if self.audit_log:
            self.audit_log.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_log.open("a") as fh:
                fh.write(json.dumps(report) + "\n")
        return report


__all__ = ["ResponseEngine", "Action", "Plan", "plan_response", "NftablesBackend", "BlocklistFileBackend"]
