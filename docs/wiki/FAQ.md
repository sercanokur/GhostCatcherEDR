# FAQ

## Why another EDR?

Most production-grade EDRs are commercial, opaque, or both. GhostCatcher is an open, inspectable Linux endpoint agent you can audit, modify, and host yourself. It is not a replacement for managed EDRs in environments that need 24/7 hunters and proprietary intel; it **is** a credible primary detection layer for teams who run their own SIEM and want auditable Linux coverage.

## How is this different from auditd or osquery?

- **auditd** captures syscalls; you still need rules and a pipeline to turn them into actionable detections. GhostCatcher consumes auditd as one of its sensor backends.
- **osquery** turns OS state into SQL. Excellent for fleet hunting; less focused on "is this host being attacked right now". GhostCatcher is opinionated about specific Linux attack patterns (web shells, persistence, fileless, reverse shells) and ships rules for them out of the box.

You can run all three together. They overlap on the data side, not on the detection side.

## Does it require an agent on every host?

Yes. GhostCatcher is a host agent. There is no agentless mode — many of the signals it uses (process ancestry, `/proc/*/maps`, fsnotify on cron, eBPF on syscalls) only exist locally.

## Does it phone home to a vendor?

No. There is no telemetry, license check, or external dependency at runtime. The agent only talks to the sinks **you** configure.

## Can it block? (active response)

Not yet. Today GhostCatcher detects, alerts, quarantines (file copy, never delete), and self-protects. Active response (kill -9, iptables drop, container halt) is intentionally deferred — the failure modes of an EDR that can stop your production workload are severe and need careful design. Track the upstream roadmap if this matters to you.

## How heavy is it?

In a typical web host with `scan_interval: 5m` and the eBPF sensor enabled:

- 1–2 % of one CPU core for scan ticks; sensor itself is < 1 %.
- 30–80 MB RSS depending on the size of `document_roots` (the web walker holds path lists, not file contents, in memory).
- Disk: baseline JSON is on the order of MB for small hosts, tens of MB for large web roots.
- Network: bounded by your sink throughput (one JSON per detection, plus periodic `WATCHDOG=1` over `NOTIFY_SOCKET`).

Heavy hosts may benefit from `scan_interval: 15m` paired with an active sensor; the eBPF/auditd path catches the time-sensitive stuff.

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

1. Create `internal/detect/<your-detector>/` with a `Scan(...) ([]event.Event, error)` function.
2. Add a baseline field if your detector needs one (see `internal/baseline/baseline.go` and `BuildBaseline*` functions).
3. Wire the call into `internal/runner/runner.go`'s scan loop.
4. Add the corresponding rule entry to `configs/rule_pack.example.yaml`.
5. Add positive + negative samples under `testdata/eval/` (and unit tests under your detector's package).
6. Run `go test ./...` and `ghostcatcher eval` locally.
7. Open a PR.

The smallest end-to-end PR you can study for shape is `internal/detect/ancestry/` — it has the same five concerns (config, baseline, scan, rule entry, test) in their minimal form.
