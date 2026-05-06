# Architecture

GhostCatcher is a single-binary agent organised into three layers: **sensors** that produce raw signals, **detectors** that interpret them, and an **engine** that scores, correlates, rate-limits, enriches, and ships the resulting events to one or more sinks.

## Process model

There is one long-lived process per host. It maintains:

- a periodic **scan loop** driven by `scan_interval` (full sweep across all detectors),
- a **realtime sensor** goroutine (`internal/sensor`) that picks the best available backend at startup and forwards exec/openat/connect/ptrace/init_module/memfd events,
- one or more **fsnotify** goroutines watching sensitive paths,
- an **emit pipeline** that runs rule expressions, the correlator, the rate limiter, and every configured sink, and
- a **selfguard** goroutine that re-hashes the agent binary and pings the systemd watchdog.

```text
                         +-----------------------+
                         |   sensor.Auto         |
                         |  ebpf | audit | proc  |
                         +-----------+-----------+
                                     |
        +-------------+--------------+--------------+--------------+
        |             |              |              |              |
+-------v-----+  +----v-----+  +-----v------+  +----v-----+  +-----v-----+
|  scan loop  |  | fsnotify |  |  ancestry  |  |   yara   |  |  ioc enrich|
| (interval)  |  |  watcher |  |  detector  |  | (optional)|  |            |
+-------+-----+  +----+-----+  +-----+------+  +----+-----+  +-----+-----+
        |             |              |              |              |
        +-------------+----+---------+--------------+--------------+
                          |
                +---------v----------+
                |  rules.Pack.Match  |  expr eval, signals merge,
                |  + correlator      |  time-windowed boost
                +---------+----------+
                          |
                +---------v----------+
                |  rate limit + dedup|
                +---------+----------+
                          |
        +-----------------+-------------------+
        |                                     |
+-------v--------+                  +---------v--------+
| sinks []       |                  |  spool (NDJSON)  |
| stdout/syslog/ |--retry-failed--->|  /var/spool/...  |
| HEC/_bulk/Loki |                  +------------------+
+-------+--------+
        |
+-------v---------+
|  quarantine     |  (file-based high-confidence events)
+-----------------+
```

## Source tree

| Directory | Role |
|-----------|------|
| `cmd/agent/` | CLI entrypoint with subcommands `run`, `check-config`, `baseline commit`, `eval`. |
| `internal/baseline/` | JSON snapshot load/save. |
| `internal/config/` | YAML configuration types and loader. |
| `internal/event/` | Schema 1.1 event struct + JSON encoder. |
| `internal/procfs/` | Helpers around `/proc` (ancestry, cgroup, env, fds, net, maps). |
| `internal/sensor/` | Realtime sensor abstraction with `ebpf` / `audit` / `procpoll` backends. |
| `internal/detect/web/` | Web shell scanner: regex set, normalization pass, entropy, magic byte, taint flow. |
| `internal/detect/ldpreload/` | `/etc/ld.so.preload` and `/proc/*/environ` checks. |
| `internal/detect/persistence/` | Cron, systemd, ssh, pam, sudoers, shellrc, users, kmods, ld.so.conf. |
| `internal/detect/memorymaps/` | RWX, `(deleted)`, TracerPid, CapEff, `.so` allowlist. |
| `internal/detect/integrity/` | dpkg/rpm verify + SUID/SGID delta + `security.capability` xattr delta. |
| `internal/detect/network/` | `/proc/net/{tcp,udp}` × `/proc/*/fd` reverse shell + listen drift. |
| `internal/detect/ancestry/` | `PROC_RARE_ANCESTRY`. |
| `internal/detect/yara/` | Stub by default; cgo-backed YARA scanner with `with_yara`. |
| `internal/rules/` | Rule pack loader, expression evaluator, Sigma-lite, ed25519 verify. |
| `internal/runner/` | Scan orchestration, dedup, correlation glue, emit. |
| `internal/ioc/` | Hash / IP / CIDR / domain feed loader + matcher. |
| `internal/quarantine/` | Tamper-resistant evidence vault. |
| `internal/selfguard/` | Binary hash check + systemd watchdog notify. |
| `internal/eval/` | Precision/recall/F1 harness used by CI. |
| `internal/watch/` | fsnotify watcher set. |
| `internal/export/` | Sink implementations (`syslog`, `syslogtcp`, `splunk`, `elastic`, `loki`). |

## Data flow

1. **Acquire.** Sensors and scanners produce candidate signals. A scan pass walks `/etc`, `/proc`, document roots, and the cron tree; the realtime sensor pushes `comm`, `pid`, `parent`, `argv`, `cgroup`, etc. into a channel.
2. **Detect.** Each detector emits zero or more `event.Event` candidates with `Signals[]` and a tentative `Confidence` and `Severity`.
3. **Match.** `rules.Pack.Match` resolves each candidate against rule definitions: it merges signals, requires `min_signals`, evaluates the optional boolean `expr`, and assigns `RuleID` / `TechniqueID` / `Tactic`.
4. **Correlate.** The sliding-window correlator (`internal/runner/correlation.go`) checks whether a peer rule fired on the same entity inside `correlate_window`. If yes, the new event gains `correlate_boost` confidence and a `CORRELATION_BOOST` signal.
5. **Enrich.** `runner.enrich` adds `process` (with ancestor `comm`s), `file`, `network`, and `container` context. It cross-references file hashes and remote IPs against IOC feeds; matches add a confidence bump and an `ioc_matches[]` entry.
6. **Gate.** `MinConfidenceAlert` decides whether the event is `learning_only` or a real alert. The per-rule rate limiter trims floods.
7. **Emit.** Every enabled sink receives the JSON line. Failures are appended to the on-disk spool; on the next successful write, the spool drains.
8. **Quarantine.** File-based events with confidence ≥ `quarantine_min_confidence` are copied to the vault with metadata.
9. **Self-protect.** The selfguard goroutine periodically re-hashes the agent binary and emits `AGENT_TAMPERED` (severity critical) if it drifts, plus pings systemd via `WATCHDOG=1`.

## Concurrency model

- Each scanner is invoked synchronously inside the scan goroutine; expensive scanners (web walking, integrity) are gated by config flags so users can drop them on small hosts.
- The realtime sensor runs in its own goroutine; juicy events (`ptrace`, `init_module`, `memfd_create`, suspicious `connect`) trigger a debounced `RunOnce` so the periodic scan is not the only line of defense.
- The fsnotify watcher debounces rapid changes (e.g. systemd reload writing many unit files) before triggering rescans.
- All sink writes are sequential per-sink; sinks do not block each other and do not block the scan loop.

## Failure model

- A single sink failure spools, never crashes; the next event drains the spool.
- A single detector failure logs at WARN and is skipped for that pass; the rest of the scan continues.
- A failed rule pack signature is fatal at startup — the agent refuses to run with an unverifiable rule set.
- A failed agent self-hash check emits `AGENT_TAMPERED` and stops pinging the watchdog, which causes systemd to restart the unit.
- A failed baseline 2FA check refuses to overwrite the snapshot.

## Where to go next

- **[Sensors](Sensors)** explains how the eBPF / auditd / proc-poll selection works and what each backend can and cannot see.
- **[Detections](Detections)** lists the actual rules.
- **[Rule Pack](Rule-Pack)** explains the YAML format, expressions, correlation, and signing.
