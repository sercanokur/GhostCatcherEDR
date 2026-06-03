# EDR Doctrine Layers

GhostCatcher maps four security doctrines into its endpoint pipeline.

## OODA — Detection and response engine

| Phase | GhostCatcher |
|-------|----------------|
| **Observe** | eBPF / auditd / proc-poll sensors + periodic scanners |
| **Orient** | `Runner.orient`: enrich, kill-chain phase, IOC, correlation |
| **Decide** | Rule pack scoring, expressions, `MinConfidenceAlert`, severity |
| **Act** | `internal/respond` (default **audit**; opt-in **enforce**) |

**Speed:** High-fidelity sensor events (ptrace, memfd, init_module, AF_ALG socket) use the **inline fast path** (`dispatchEvent`) so Observe→Act completes in milliseconds. Periodic scans are the **safety net** for at-rest state.

**Dwell time:** Each event may include `response.loop_latency_ms` (sensor observe time → Act).

## Kill Chain — Where to intervene

Rules may set `kill_chain_phase` or inherit a phase from `tactic` via `internal/killchain`. Early phases (`exploitation`, `installation`) can trigger stronger response actions sooner.

## MITRE ATT&CK — Rule language

Every rule carries `techniques` and `tactic`; events emit `technique_id` and `tactic`. Run coverage analysis:

```bash
ghostcatcher coverage -config /etc/ghostcatcher/config.yaml
ghostcatcher coverage -config /etc/ghostcatcher/config.yaml -navigator /tmp/layer.json
ghostcatcher coverage -config /etc/ghostcatcher/config.yaml -gaps
```

## Defense in depth — EDR boundaries

| Layer | Role |
|-------|------|
| Perimeter | Upstream of the agent (firewall, WAF) |
| **Endpoint (this agent)** | `defense_layer: endpoint` on every event |
| SIEM | Syslog / Splunk HEC / Elastic / Loki sinks |
| SOC | `soc_escalate: true` on high/critical severity or non-alert response |

EDR does not replace perimeter or SOC. It shortens dwell time on the host.

## Credential dumping example (T1003 analog)

1. **ATT&CK:** `T1003` on rule `CREDENTIAL_ACCESS_PROC_DUMP`
2. **EDR rule:** suspicious `/proc` or ptrace pattern → live sensor fast path
3. **OODA:** Observe (sensor) → Orient (T1003, `actions-on-objectives`) → Decide (confidence ≥ threshold) → Act (`kill_process` in audit or enforce)
4. **Kill Chain:** chain break at actions-on-objectives (or installation if earlier)
5. **Defense in depth:** JSON alert to SIEM with `soc_escalate: true`

Configure response in `respond:` — see [Configuration](Configuration).
