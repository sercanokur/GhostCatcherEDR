# Architecture

GhostCatcher is a single-binary agent organised into **sensors**, **detectors** (grouped by bhv macros), and an **engine** that applies taxonomy metadata, scores, correlates (including CHAIN-1…6), rate-limits, enriches, runs OODA Act, and ships schema **1.3** events.

## Process model

One long-lived process per host maintains:

- a periodic **scan loop** (`scan_interval`) across detectors,
- a **realtime sensor** (`internal/sensor`) — best of eBPF → auditd → proc-poll,
- **fsnotify** watchers on sensitive paths (trigger rescans; FIM deltas also come from scanners),
- an **emit pipeline**: Orient (enrich + taxonomy) → rule `expr` → pairwise + chain correlation → rate limit / dedup → Act (`internal/respond`) → sinks,
- a **live-sensor fast path** for high-fidelity kinds (`exec`, `openat`, `connect`, `ptrace`, `memfd`, `init_module`, `socket`),
- **sudden-root** credential polling and **selfguard** binary hash + systemd watchdog.

```text
                         +-----------------------+
                         |   sensor.Auto         |
                         |  ebpf | audit | proc  |
                         +-----------+-----------+
                                     |
        +-------------+--------------+--------------+--------------+
        |             |              |              |              |
+-------v-----+  +----v-----+  +-----v------+  +----v-----+  +-----v-----+
|  scan loop  |  | fsnotify |  |  live nano |  |   yara   |  |  ioc enrich|
| (interval)  |  |  watcher |  |  routers   |  | (optional)|  |            |
+-------+-----+  +----+-----+  +-----+------+  +----+-----+  +-----+-----+
        |             |              |              |              |
        +-------------+----+---------+--------------+--------------+
                          |
                +---------v----------+
                |  orient + taxonomy |
                |  mapping.yaml Apply|
                +---------+----------+
                          |
                +---------v----------+
                |  pack score + expr |
                |  correlate + CHAIN |
                +---------+----------+
                          |
                +---------v----------+
                |  respond (OODA Act)|
                |  rate limit + dedup|
                +---------+----------+
                          |
        +-----------------+-------------------+
        |                                     |
+-------v--------+                  +---------v--------+
| sinks []       |                  |  spool (NDJSON)  |
| stdout/syslog/ |--retry-failed--->|  /var/spool/...  |
| HEC/_bulk/Loki |                  +------------------+
+----------------+
```

## Source tree

| Directory | Role |
|-----------|------|
| `cmd/agent/` | CLI: `run`, `check-config`, `baseline commit`, `eval`, `coverage`. |
| `cmd/demo-console/` | Local kill-chain demo UI. |
| `configs/mapping.yaml` | bhv Macro→Micro→Nano catalog + CHAIN definitions. |
| `configs/lab_rule_pack.yaml` | Full-catalog scoring (lab). |
| `configs/rule_pack.example.yaml` | Production-oriented rule subset. |
| `bhv.md` | Human-readable Ubuntu behavior tree. |
| `internal/event/` | Schema **1.3** event contract + `NewFinding`. |
| `internal/taxonomy/` | Load/apply `mapping.yaml`. |
| `internal/anchor/` | cgroup → systemd unit primary anchor. |
| `internal/baseline/` | JSON snapshot load/save. |
| `internal/config/` | YAML config (`mapping_path`, `watched_units`, `fp_allowlist_units`, …). |
| `internal/procfs/` | `/proc` helpers. |
| `internal/sensor/` | eBPF / auditd / proc-poll backends. |
| `internal/detect/web/` | Web shells, docroot write, upload dirs, worker children. |
| `internal/detect/persistence/` | SSH, cron, systemd, PAM, sudoers, profile, users, kmods. |
| `internal/detect/fimextra/` | Ubuntu M2.4 / SSH drop-ins / log truncate FIM deltas. |
| `internal/detect/ldpreload/` | `ld.so.preload` + `LD_PRELOAD` env. |
| `internal/detect/memorymaps/` | RWX, deleted exe, writable maps, tracer, masquerade. |
| `internal/detect/integrity/` | dpkg hash verify, SUID/SGID, capabilities. |
| `internal/detect/network/` | Socket stdio, listen new, web egress, IMDS. |
| `internal/detect/ancestry/` | `PROC_RARE_ANCESTRY`. |
| `internal/detect/privesc/` | `PROC_SUDDEN_ROOT`. |
| `internal/detect/defense/` | AppArmor/sysctl/firewall/GTFOBins/tmpfs exec/journal. |
| `internal/detect/credential/` | Shadow/SSH/cloud/app secret access (live openat). |
| `internal/detect/containeresc/` | Docker/LXD/runc/cgroup escape patterns. |
| `internal/detect/sensorlive/` | ptrace / memfd / init_module live nanos. |
| `internal/detect/copyfail/` | CVE-2026-31431. |
| `internal/detect/yara/` | Optional YARA (build tag). |
| `internal/rules/` | Rule pack, expr, Sigma-lite, ed25519. |
| `internal/runner/` | Orchestration, correlator (pairwise + chains), emit. |
| `internal/respond/` | OODA Act. |
| `internal/killchain/` | Tactic → Lockheed phase. |
| `internal/attack/` | ATT&CK coverage / Navigator layer. |
| `internal/ioc/` | Hash / IP / CIDR / domain feeds. |
| `internal/quarantine/` | Evidence vault. |
| `internal/selfguard/` | Binary hash + systemd watchdog. |
| `internal/eval/` | Precision/recall harness. |
| `internal/watch/` | fsnotify sensitive paths. |
| `internal/export/` | syslog / TCP syslog / Splunk / Elastic / Loki. |

## Data flow

1. **Acquire.** Periodic scanners + live sensor + fsnotify produce candidates. Live kinds are routed to nano-specific handlers (credential openat, defense exec, container file/exec, web docroot write, IMDS connect, sensorlive, sudden-root, copyfail).
2. **Detect.** Detectors emit `event.Event` with `Signals[]` and tentative confidence. `src` reflects the real backend (`AUDIT` / `PROCSCAN` / `FIM` / `INVENTORY`) until eBPF decode is complete.
3. **Orient.** Enrich process (including `cgroup` / `systemd_unit`), container, IOC; set `anchor`; `taxonomy.Apply` fills macro/micro/src/type/conf_band; derive `kill_chain_phase` and `defense_layer: endpoint`.
4. **Decide.** Rule pack scores; optional `expr` may force `learning_only`; pairwise `correlate` and ordered **CHAIN-1…6** may boost confidence and set `chain_id` / `evidence_loss`.
5. **Act.** `respond.Decide` / `Apply` (audit or enforce).
6. **Gate.** `MinConfidenceAlert`, dedup, per-rule rate limit.
7. **Emit.** stdout JSONL + sinks; spool on failure; quarantine high-confidence files; selfguard may emit `AGENT_TAMPERED` (M3.3).

## Concurrency model

- Full, FIM, and inventory scans share a mutex (`TryLock`); overlapping ticker/fsnotify requests are skipped and counted.
- Network scans are further throttled by `network_scan_interval` (default 15m); inventory (SUID/dpkg) uses `integrity_scan_interval` (default 6h).
- Expensive detectors (network, ancestry, copy-fail page-cache, …) stay on the periodic full scan; fsnotify triggers `RunFIMOnce`.
- Baseline JSON is mtime/size-cached across scans; web content reads skip when baseline mtime(+size) still matches.
- Sensor producers use non-blocking emit (`sensor.channel_drop` / `ringbuffer.overrun` counters); optional `sensor.debounce_ms` coalesces the OODA fast path.
- Host budget lines (`scan.budget`) log `duration_ms`, `proc_reads`, `hash_bytes`, and sensor drop counters.
- The sensor consumer runs in its own goroutine and dispatches live nanos inline (milliseconds Observe→Act).
- fsnotify debounces bursts before triggering the light FIM path.
- Sink writes are sequential per sink and do not block the scan loop.

## Failure model

- Sink failure → spool, never crash.
- Detector failure → WARN, continue scan.
- Unverifiable signed rule pack → refuse to start.
- Self-hash mismatch → `AGENT_TAMPERED`, stop watchdog pings (systemd restarts).
- Baseline 2FA failure → refuse overwrite.

## Where to go next

- **[Behavior Taxonomy](Behavior-Taxonomy)** — Macro/Micro/Nano and chains.
- **[Sensors](Sensors)** — backend selection and live routing.
- **[Detections](Detections)** — nano inventory.
- **[Rule Pack](Rule-Pack)** — YAML scoring and expressions.
