# EDR Doctrine Layers

GhostCatcher maps security doctrines onto its endpoint pipeline. The Ubuntu **Macro → Micro → Nano** tree ([Behavior Taxonomy](Behavior-Taxonomy), [`bhv.md`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/bhv.md)) is the detection vocabulary; OODA / Kill Chain / ATT&CK are how those nanos are processed and reported.

## Behavior tree — what we detect

| Macro | Doctrine role |
|-------|----------------|
| M1 Web RCE | Initial foothold / webshell / worker abuse |
| M2 Persistence | Installation via SSH/cron/systemd/Ubuntu hooks |
| M3 Privesc & defense | Exploitation / defense evasion |
| M4 Concealment | Anti-forensics / evidence loss |
| M5 Credentials | Actions on objectives (secrets) |
| M6 Container escape | Host boundary violation |

Nanos are the atomic `rule_id`s. Chains (CHAIN-1…6) encode multi-step stories with saturating CRITICAL scores.

## OODA — Detection and response engine

| Phase | GhostCatcher |
|-------|----------------|
| **Observe** | eBPF / auditd / proc-poll + periodic FIM/INVENTORY/PROCSCAN |
| **Orient** | Enrich + **taxonomy.Apply** + kill-chain phase + IOC + anchor |
| **Decide** | Pack scoring, `expr`, pairwise correlate, **CHAIN-1…6**, thresholds |
| **Act** | `internal/respond` (default **audit**; opt-in **enforce**) |

**Speed:** Live kinds (`exec`, `openat`, `connect`, `ptrace`, `memfd`, `init_module`, `socket`) use the inline fast path so Observe→Act is milliseconds. Periodic scans are the safety net for at-rest state.

**Dwell time:** Events may include `response.loop_latency_ms`.

## Kill Chain — Where to intervene

Rules may set `kill_chain_phase` or inherit from `tactic` via `internal/killchain`. Early phases (`exploitation`, `installation`) can prefer stronger Act actions.

## MITRE ATT&CK — Rule language

Every nano carries `techniques` / `tactic` (from pack and/or `mapping.yaml`). Events emit `technique_id` and `tactic`. Coverage:

```bash
ghostcatcher coverage -config /etc/ghostcatcher/config.yaml
ghostcatcher coverage -config /etc/ghostcatcher/config.yaml -navigator /tmp/layer.json
ghostcatcher coverage -config /etc/ghostcatcher/config.yaml -gaps
```

Baseline technique list lives in `internal/attack/catalog.go` (includes T1552.005 IMDS, T1611 escape, T1620 reflective load, etc.).

## Defense in depth — EDR boundaries

| Layer | Role |
|-------|------|
| Perimeter | Upstream (firewall, WAF) |
| **Endpoint (this agent)** | `defense_layer: endpoint` on every event |
| SIEM | Syslog / Splunk HEC / Elastic / Loki |
| SOC | `soc_escalate` on high/critical or non-alert response |

## Example — Web RCE → cloud credentials (CHAIN-2)

1. **Nanos:** `WEB_WORKER_INTERP_CHILD` → `NETWORK_IMDS_ACCESS` → `CLOUD_CRED_FILE_ACCESS`
2. **ATT&CK:** T1059.006, T1552.005, T1552.001
3. **OODA:** Observe (exec + connect + openat) → Orient (same `anchor`/unit, taxonomy M1/M5) → Decide (chain CRITICAL) → Act (audit `alert_only` or escalate)
4. **Kill Chain:** exploitation → actions-on-objectives
5. **SIEM:** schema 1.3 JSON with `chain_id: CHAIN-2`, `macro`/`micro`, `conf_band`

Configure Act in `respond:` — see [Configuration](Configuration).
