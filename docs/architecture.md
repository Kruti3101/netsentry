# Architecture and design notes

## Data model

Every telemetry source is normalised to `FlowRecord` (`netsentry/models.py`), which has:

- the 5-tuple, timestamps and duration
- per-direction packet and byte counts
- a Zeek-style `conn_state` when known, otherwise cumulative TCP flags

Detectors only ever see `FlowRecord`s.

| Source | Notes |
|---|---|
| Zeek `conn.log` | TSV (honours `#separator` / `#fields`) or JSON lines, optionally gzipped. `history` is mapped to cumulative flags. |
| NetFlow / IPFIX | nfdump `-o csv` or any CSV, resolved through a column-alias table. Flags may be nfdump strings (`...A.S.`) or integer bitmasks. Records are unidirectional. |
| PCAP | Dependency-free reader. Packets are assembled into bidirectional flows with a 60 s idle timeout, and `conn_state` is derived (`S0`, `REJ`, `SF`, `S1`, `RSTO`/`RSTR`, `OTH`). |

## Why per-service baselines

A single global traffic baseline hides attacks on small services inside the noise of large ones. Keying on `(dst, dport, proto)` lets a flood against a quiet SSH bastion stand out, even when it is tiny next to the web frontend's normal load.

Reflected traffic is keyed as `(victim, -abused_port, "udp-amp")`, so all NTP or DNS responses converging on a victim aggregate in one place, whatever random destination ports they hit.

## EWMA update

The update uses West's incremental form:

```
diff  = x - mean
incr  = α · diff
mean += incr
var   = (1 - α) · (var + diff · incr)
z     = (x - mean_prev) / max(√var_prev, rel_floor · mean_prev, 1)
```

With α = 0.1 the effective memory is about 10 windows (100 s at the default window). Windows classified as floods are skipped during the update; this is baseline-poisoning protection. After `max_freeze_windows` consecutive anomalous windows, learning resumes so a permanent shift doesn't alert forever.

The KQL ports implement the same recurrence as an IIR filter: `series_iir(x, [α], [1, α-1])`. The variance comes from an EWMA of x² minus the square of the EWMA of x.

## Response safety model

Automated blocking is the part most likely to cause an outage, so the policy layer is conservative by construction:

1. **Dry run by default.** Enforcement needs `--apply` or `response.dry_run: false`.
2. **Never block a victim.** Floods produce rate limits toward the victim, never a block of it.
3. **Never block spoofed sources.** Sources are attributed only when they carry at least 1% of attack packets.
4. **Internal hosts need a human.** Actions on internal IPs carry `requires_approval` and are never auto-applied.
5. **Everything expires.** Blocks have TTLs; the blocklist file prunes expired entries on load.
6. **Everything is audited.** Each run is appended to `state/audit.jsonl` with its actions, skips and backend results.

## LLM triage threat model

The triage agent reads data that attackers partly control: HTTP user agents, hostnames, DNS names. The design assumes some of that data is adversarial.

- **Prompt injection:** untrusted fields are fenced and labelled. The system prompt forbids following instructions found in them, and the eval set includes an injection case.
- **Hallucination:** decisions must cite evidence IDs. The validator mechanically checks citations, technique IDs and every IP in the rationale against the context.
- **Unverified output:** invalid output gets one repair attempt, then falls back to human review. The triage verdict is advisory; automated enforcement is driven by the detector confidence and the policy guardrails, not by the LLM.
- **Bias:** geography and ASN are provided as context but marked non-dispositive. The eval measures per-slice gaps and counterfactual verdict flips.
