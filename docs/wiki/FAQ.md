# FAQ

## Why another EDR?

Most production-grade EDRs are commercial, opaque, or both. GhostCatcher is an open, inspectable Linux endpoint agent you can audit, modify, and host yourself. It is not a replacement for managed EDRs in environments that need 24/7 hunters and proprietary intel; it **is** a credible primary detection layer for teams who run their own SIEM and want auditable Linux coverage.

## How is this different from auditd or osquery?

- **auditd** captures syscalls; you still need rules and a pipeline to turn them into actionable detections. GhostCatcher consumes auditd as one of its sensor backends and maps them to bhv **nanos**.
- **osquery** turns OS state into SQL. Excellent for fleet hunting; less focused on "is this host being attacked right now". GhostCatcher is opinionated about Ubuntu Macro→Micro→Nano behaviors (web RCE, persistence, privesc, concealment, credentials, container escape) and ships CHAIN-1…6 correlation on top.

You can run all three together. They overlap on the data side, not on the detection side.

## What is schema 1.3 / `mapping.yaml`?

Schema **1.3** adds taxonomy fields (`macro`, `micro`, `src`, `type`, `anchor`, `conf_band`, `chain_id`, `evidence_loss`) to every event. `mapping.yaml` is the machine-readable catalog of every nano and the six correlation chains. See **[Behavior Taxonomy](Behavior-Taxonomy)**.

## Does it require an agent on every host?

Yes. GhostCatcher is a host agent. There is no agentless mode — many of the signals it uses (process ancestry, `/proc/*/maps`, fsnotify on cron, eBPF on syscalls) only exist locally.

## Does it phone home to a vendor?

No. There is no telemetry, license check, or external dependency at runtime. The agent only talks to the sinks **you** configure.

## Can it block? (active response)

Yes, with guardrails. The OODA **Act** phase is implemented in `internal/respond` and defaults to **`mode: audit`** (logs the intended action only). Set `respond.mode: enforce` and enable per-action flags (`allow_kill_process`, `allow_quarantine`, `allow_isolate_host`) to actually kill processes, copy artifacts to the vault, or apply coarse host isolation (Linux + root). Protected PIDs/comms, rate limits, and `kill_switch` prevent accidents. See **[Doctrine](Doctrine)** and `respond:` in **[Configuration](Configuration)**.

## How heavy is it?

With the **balanced** profile (`configs/profiles/balanced.yaml`: `scan_interval: 5m`, sensor `auto`, page-cache check off, inventory on a 6h ticker):

- Scan ticks: typically **well under 1–2 % of one core** on a small docroot; watch for `scan.budget` / `duration_ms` in the journal.
- Sensor: **&lt; 1 %** when eBPF/auditd is healthy; userland falls back to `/proc` poll only if both are unavailable.
- RSS: **~30–80 MB** driven mainly by `document_roots` size (path lists + rule pack), not by holding file contents.
- Disk: baseline JSON is MBs on small hosts, tens of MB on large web roots.
- Network: bounded by sink throughput (one JSON per detection).

Pick a profile instead of inventing knobs:

| Profile | Use when |
|---------|----------|
| `configs/profiles/light.yaml` | Constrained VMs; 15m scan, ancestry off, `debounce_ms: 50` |
| `configs/profiles/balanced.yaml` | Default production |
| `configs/profiles/heavy-host.yaml` | Large CMS / dense PID tables; 15m scan, longer network/inventory |
| `configs/profiles/lab.yaml` | Demo only — **do not** copy 1m / `sudden_root: 1s` to prod |

Local load checks: `go test -bench=BenchmarkWebScan_Busy ./internal/detect/web/` (500-file docroot) and `go test -bench=BenchmarkSuddenRootSnapshot ./internal/detect/privesc/` (walks live `/proc`).

## Why YARA behind a build tag?

YARA is excellent and we want it available, but cgo + libyara turns the binary into a per-distro artifact and adds a CVE surface to track. Most users do not need YARA scanning to get value from GhostCatcher — the regex + taint + entropy stack already covers most public web shells. When you do need YARA (custom hunting rules, response to a specific intel push), enable `with_yara` and ship the cgo build.

## Why eBPF behind a build tag?

eBPF is pure Go via `cilium/ebpf` (no cgo), but the kernel API surface is moving fast and not every host has a kernel + capability combination that allows attaching tracepoints. Keeping it behind a tag lets the default build remain a static binary that runs everywhere, while operators who *do* have a modern kernel can opt in.

## Can I sign the rule pack with minisign or sigstore?

Today the agent verifies an ed25519 detached signature created with `openssl pkeyutl -sign`. The wire format matches what minisign and other ed25519 tools produce. A `cosign sign-blob` flow is on the roadmap; for now if you already have a sigstore signing pipeline, post-process its output into a raw 64-byte ed25519 signature.

## Can I write rules in Sigma?

A subset, yes. See **[Rule Pack → Sigma-lite drop-ins](Rule-Pack)**. The full Sigma syntax is much larger than the EDR-relevant subset; the agent transpiles what it can and warns on what it cannot.

## How are alerts deduplicated?

Each event has a `dedup_key` derived from `rule_id` + the entity identifier (path, socket tuple, process exe + args). Repeats within the rule's `dedup_window` (default = `scan_interval`) are suppressed. The first event still goes out; the dedup applies to the second through Nth.

## What happens if I lose the baseline file?

The agent boots in "no baseline" mode: every detector behaves as if everything is new. Set `learning_mode: true` and rebuild the baseline ASAP — see **[Operations Runbook → First baseline](Operations-Runbook)**.

## Does it support Windows or macOS?

No. Linux-only at runtime. macOS is supported only as a *development* environment (the pure-Go default build compiles and most unit tests pass; `/proc`-dependent scanners noop with a warning).

## How do I tell which version is running?

```bash
journalctl -u ghostcatcher -n 1 -o cat | jq .agent_version
```

Or watch the first stderr line at startup, which logs `agent_version` and the active build tags.

## Where do I file bugs / feature requests?

GitHub issues on the main repository. Security-sensitive issues should follow the policy in [`SECURITY.md`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/SECURITY.md) — please do not open public issues for undisclosed vulnerabilities.

## Can I commercialize this?

Check the `LICENSE` file in the repository for the actual terms. The project's intent is to be useful to commercial security teams; building paid services around it is fine within those terms.

## I want to add a new detector. Where do I start?

1. Pick Macro/Micro and a **nano ID** in SCREAMING_SNAKE; add it to `configs/mapping.yaml` (and preferably `bhv.md`).
2. Create `internal/detect/<pkg>/` with `Scan` and/or a live `Route*` for sensor kinds.
3. Add baseline fields if needed (`internal/baseline`).
4. Wire into `runner.RunOnce` and/or `consumeSensor`.
5. Add scoring to `configs/lab_rule_pack.yaml` (and production pack if shipping).
6. Prefer `watched_units` / cgroup **anchor** over process names.
7. Add positive + negative tests; run `go test ./...` and `ghostcatcher eval`.
8. Update **[Detections](Detections)** / wiki in the same PR.

Study `internal/detect/ancestry/` for a small scan-only shape, or `internal/detect/credential/` for live `openat` routing.
