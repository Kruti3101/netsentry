"""Enforcement backends.

* :class:`NftablesBackend` renders (and optionally applies) nftables rules:
  timed blocklist sets plus per-source rate-limit meters.
* :class:`BlocklistFileBackend` maintains a JSON blocklist with expiries and a
  plain-text export that edge firewalls / ipset / cloud WAFs can ingest.

Everything is dry-run unless ``dry_run=False`` is passed explicitly.
"""
from __future__ import annotations

import json
import re
import shlex
import subprocess
import time
from pathlib import Path

from .policy import Action


def _safe_ident(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", s)


class NftablesBackend:
    name = "nftables"

    def __init__(self, table: str = "netsentry", dry_run: bool = True):
        self.table = _safe_ident(table)
        self.dry_run = dry_run

    def bootstrap(self) -> list[str]:
        t = self.table
        return [
            f"add table inet {t}",
            f"add set inet {t} block_src {{ type ipv4_addr; flags timeout; }}",
            f"add set inet {t} block_dst {{ type ipv4_addr; flags timeout; }}",
            f"add chain inet {t} input {{ type filter hook input priority -10; policy accept; }}",
            f"add chain inet {t} forward {{ type filter hook forward priority -10; policy accept; }}",
            f"add chain inet {t} output {{ type filter hook output priority -10; policy accept; }}",
            f"add rule inet {t} input ip saddr @block_src drop",
            f"add rule inet {t} forward ip saddr @block_src drop",
            f"add rule inet {t} forward ip daddr @block_dst drop",
            f"add rule inet {t} output ip daddr @block_dst drop",
        ]

    def render(self, a: Action) -> list[str]:
        t = self.table
        if a.kind in ("block_src", "block_dst"):
            return [f"add element inet {t} {a.kind} {{ {a.target} timeout {a.ttl}s }}"]
        if a.kind == "rate_limit" and a.proto == "tcp":
            meter = _safe_ident(f"syn_{a.dst}_{a.dport}")
            return [f"add rule inet {t} forward ip daddr {a.dst} tcp dport {a.dport} "
                    f"tcp flags & (syn|ack) == syn meter {meter} {{ ip saddr limit rate over {a.pps}/second }} drop"]
        if a.kind == "rate_limit" and a.proto == "udp":
            meter = _safe_ident(f"udp_{a.dst}_{a.dport}")
            return [f"add rule inet {t} forward ip daddr {a.dst} udp dport {a.dport} "
                    f"meter {meter} {{ ip saddr limit rate over {a.pps}/second }} drop"]
        if a.kind == "drop_reflection":
            return [f"add rule inet {t} forward ip daddr {a.dst} udp sport {a.sport} ct state new drop"]
        raise ValueError(f"unsupported action {a.kind}")

    def apply(self, a: Action) -> dict:
        cmds = self.render(a)
        if self.dry_run or a.requires_approval:
            return {"backend": self.name, "applied": False, "commands": [f"nft {c}" for c in cmds],
                    "note": "approval required" if a.requires_approval else "dry run"}
        for c in cmds:
            subprocess.run(["nft", *shlex.split(c)], check=True, capture_output=True, text=True)
        return {"backend": self.name, "applied": True, "commands": [f"nft {c}" for c in cmds]}


class BlocklistFileBackend:
    name = "blocklist-file"

    def __init__(self, path: str | Path, dry_run: bool = True, now=time.time):
        self.path = Path(path)
        self.dry_run = dry_run
        self.now = now

    def load(self) -> dict:
        if not self.path.exists():
            return {}
        data = json.loads(self.path.read_text())
        t = self.now()
        return {ip: e for ip, e in data.items() if e["expires"] > t}

    def apply(self, a: Action) -> dict:
        if a.kind not in ("block_src", "block_dst"):
            return {"backend": self.name, "applied": False, "note": "not a block action"}
        if self.dry_run or a.requires_approval:
            return {"backend": self.name, "applied": False, "entry": a.target,
                    "note": "approval required" if a.requires_approval else "dry run"}
        data = self.load()
        data[a.target] = {"expires": self.now() + (a.ttl or 3600), "direction": a.kind,
                          "reason": a.reason, "alert_id": a.alert_id}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
        tmp.replace(self.path)
        self.path.with_suffix(".txt").write_text("\n".join(sorted(data)) + "\n")
        return {"backend": self.name, "applied": True, "entry": a.target}
