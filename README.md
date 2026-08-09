# GhostCatcher (endpoint agent)

A **Linux endpoint** detection agent written in **Go**. It runs as a CLI or **systemd** service, scans the host on an interval, streams from a runtime-selected **eBPF / auditd / /proc** sensor, watches sensitive paths via **fsnotify**, and emits **one JSON object per line** (schema **1.3**) on stdout plus any configured enterprise sinks (UDP/TCP/TLS syslog, Splunk HEC, Elastic `_bulk`, Grafana Loki).

Detections follow an Ubuntu-focused **Macro → Micro → Nano** behavior tree ([`bhv.md`](bhv.md), [`configs/mapping.yaml`](configs/mapping.yaml)): web RCE, admin persistence, privilege escalation / defense weakening, concealment, credential access, and container escape. Non-bhv rules (YARA, Copy Fail CVE legs, agent tamper, capability escalation) stay mapped to the nearest macro. Correlation prefers **cgroup / systemd unit anchors** (not process names) and ordered **CHAIN-1…6** stories.

> **Scope:** No kernel driver, no TLS inspection, no managed cloud backend. Single binary by default; optional cgo / kernel features (YARA, eBPF) live behind build tags.

Long-form docs: [`docs/wiki/`](docs/wiki/) (GitHub Wiki source). Start with [Getting Started](docs/wiki/Getting-Started.md) and [Behavior Taxonomy](docs/wiki/Behavior-Taxonomy.md).

---

## Mission

Advanced **APT** groups treat Linux as a first-class target: living off the land via built-in tools, legitimate services, and normal admin paths. GhostCatcher shortens the window those behaviors go unseen on the host—web-layer backdoors, preload evasion, stolen trust in keys and schedulers, privesc, credential theft, and container breakout—using inspectable rules you can tune and feed into a SIEM. It complements IDS and EDR; it does not replace depth across the full kill chain.

---

## Table of contents

- [Mission](#mission)
- [Features](#features)
- [What it detects (summary)](#what-it-detects-summary)
- [Requirements](#requirements)
- [Build](#build)
- [Continuous integration](#continuous-integration)
- [Quick start](#quick-start)
- [Install on a server (production)](#install-on-a-server-production)
- [Configuration checklist](#configuration-checklist)
- [SIEM integration (syslog / HEC / bulk / Loki)](#siem-integration-syslog--hec--bulk--loki)
- [Stop or disable the service](#stop-or-disable-the-service)
- [Configuration](#configuration)
- [Rule pack](#rule-pack)
- [Output format](#output-format)
- [Privileges](#privileges)
- [Project layout](#project-layout)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [License](#license)
- [Security](#security)

---

## Features

### Behavior taxonomy (schema 1.3)

| Area | Mechanism |
|------|-----------|
| **Macro → Micro → Nano** | Catalog in [`configs/mapping.yaml`](configs/mapping.yaml); doctrine in [`bhv.md`](bhv.md). Events carry `macro`, `micro`, `src`, `type`, `anchor`, `conf_band`. |
| **Anchors** | Primary correlation key is systemd unit / cgroup (`watched_units`), not `comm`. Benign noise units via `fp_allowlist_units`. |
| **CHAIN-1…6** | Ordered, same-anchor, time-windowed stories (web RCE path, IMDS/creds, privesc, defense wipe, container escape, evidence loss). Hits set `chain_id`, often `critical`, and optionally `evidence_loss`. |
| **OODA Act** | Optional active response (`internal/respond`): alert-only by default; kill / quarantine / isolate gated by policy, rate limits, and protected targets. |

### Detection surface

| Macro | Area | Mechanism |
|-------|------|-----------|
| **M1** | **Web / internet-facing exec** | PHP/JSP/ASPX/… pattern scan after normalization; Shannon entropy, magic/polyglot mismatch, ownership heuristics; **PHP taint-flow** mini-parser; docroot exec writes (`fimextra` / `web`); web-worker children split into **`WEB_WORKER_{RECON,SHELL,INTERP,DOWNLOADER}_CHILD`** + `PROC_PTY_SPAWN`; `WEB_SHELL_PATTERN` requires an exec primitive plus an input channel. |
| **M1** | **Network** | `/proc/net/tcp[6]` + `/proc/*/fd`: **`PROC_SOCKET_STDIO`** (stdio↔socket reverse shell), **`NETWORK_LISTEN_NEW`**, web-worker egress / IMDS (`NETWORK_IMDS_ACCESS`); CIDR allowlists. |
| **M2** | **Admin persistence** | SSH `authorized_keys` / `sshd_config` deltas; cron / anacron / at (base64-decoded risk tokens); systemd units/timers; **`PROFILE_HOOK`** (shell RC / profile); PAM, sudoers, users (`/etc/passwd`/`shadow`), ld.so.conf, modules-load; Ubuntu hooks via **`fimextra`** (cron.d run-parts evasion, timers, etc.). |
| **M3** | **Privesc / defense weaken** | `LD_PRELOAD` / `ld.so.preload`; dpkg md5sums or `rpm -Va` → **`LIB_HASH_MISMATCH`**; SUID/capability drift; **`PROC_SUDDEN_ROOT`**; Copy Fail CVE legs; **`defense`** (sysctl / AppArmor / auditd tamper). |
| **M4** | **Concealment** | `/proc/*/maps` RWX / `(deleted)` / TracerPid / CapEff / `.so` allowlist; live sensor routing (**`sensorlive`**, **`PROC_MEMFD_EXEC`**, **`PROC_PTRACE_INJECT`**, **`KERNEL_MODULE_LOAD`**). |
| **M5** | **Credentials** | Shadow / SSH key / agent socket / cloud-cred / app-secret / cross-UID `/proc/*/mem` mass access (`detect/credential`). |
| **M6** | **Container escape** | Docker/LXD socket abuse, setns, host mounts (`detect/containeresc`). |
| — | **YARA** | Optional `-tags with_yara`: disk + process memory → `YARA_DISK_MATCH` / `YARA_PROCESS_MATCH`. |
| — | **IOC feeds** | Hash / IP / CIDR / domain flat files; confidence boosts on match. |
| — | **Container context** | Docker / containerd / cri-o / k8s / LXC IDs from cgroup. |
| — | **Self-guard** | Agent binary sha256 drift → `AGENT_TAMPERED`; systemd `WATCHDOG=1`. |

### Engine

| Area | Mechanism |
|------|-----------|
| **Rule engine** | Per-rule MITRE techniques, `min_signals`, score weights, optional CEL-style **`expr`**, `correlate` peers, optional `response.action`, taxonomy hints (`macro`/`micro`/`src`/`type`/`conf`). |
| **Pairwise + chain correlation** | Rule-pack `correlate` windows plus mapping-defined CHAIN-1…6. |
| **Sigma-lite** | Drop `*.yml` under `sigma_lite_dir`; subset transpiled to native expressions. |
| **Signed rule packs** | Optional ed25519 detached signature; fail closed on mismatch. |
| **Rate limit + spool** | Per-rule emit cap + NDJSON spool when sinks are down. |
| **Quarantine vault** | High-confidence files under `<vault>/<YYYYMMDD>/<sha256>.bin` + JSON sidecar. |
| **Baseline commit 2FA** | Optional token via `baseline_commit_token_env`. |

### Sinks

| Transport | Notes |
|-----------|-------|
| stdout JSONL | Always enabled. |
| **UDP syslog** | RFC5424 or RFC3164. |
| **TCP / TLS syslog** | RFC5425 octet-framed; optional CA + SNI. |
| **Splunk HEC** | `{"event": …}` with sourcetype / index. |
| **Elasticsearch `_bulk`** | NDJSON; API key or basic auth; optional `insecure` TLS. |
| **Grafana Loki** | `/loki/api/v1/push` with static + per-event labels. |

Baseline is JSON (`baseline commit`). Alerts respect **`min_confidence_for_alert`** and **`learning_mode`** until you freeze a baseline.

---

## What it detects (summary)

Rules live in the YAML **rule pack**; taxonomy IDs live in **`mapping.yaml`**. Production-oriented subset: [`configs/rule_pack.example.yaml`](configs/rule_pack.example.yaml). Lab/full catalog scoring: [`configs/lab_rule_pack.yaml`](configs/lab_rule_pack.yaml).

MITRE-style coverage includes (non-exhaustive):

- **T1505.003** / **T1059.004** / **T1059.006** — web shells, worker children (recon/shell/interp/downloader), reverse-shell stdio sockets.
- **T1574.006** / **T1014** — `LD_PRELOAD`, `ld.so.preload`, suspicious module loads.
- **T1098.004** / **T1136.001** — authorized key fingerprints, local users, UID-0 accounts.
- **T1053.003** / **T1053.006** — cron + systemd timer deltas.
- **T1055** / **T1620** — RWX maps, memfd exec, ptrace inject.
- **T1036** — package hash mismatch (`LIB_HASH_MISMATCH`).
- **T1556.003** / **T1548.003** — PAM / sudoers paths.
- **T1562.001** — agent binary tamper (`AGENT_TAMPERED`).
- **T1571** / **T1041** / **T1071.001** — new listens, egress, IMDS.
- **T1068** — Copy Fail AF_ALG + page-cache poisoning; behavior-only sudden root (`PROC_SUDDEN_ROOT`).

Scoring, correlation, and expressions: see the rule pack. Chain definitions: [`configs/mapping.yaml`](configs/mapping.yaml).

---

## Requirements

- **Go** **1.25+** to build from this module ([`go.mod`](go.mod)); CI uses **1.26.5**.
- **Runtime:** Linux. Integrity backends auto-select `dpkg` (Debian/Ubuntu) or `rpm` (RHEL/CentOS/Fedora) via `/etc/os-release`. Ubuntu is the primary doctrine target for `bhv.md`.
- **Optional (cgo):** [YARA ≥ 4.3](https://virustotal.github.io/yara/) for `-tags with_yara`.
- **Optional (kernel):** Linux ≥ 5.8, `CONFIG_BPF_SYSCALL=y`, and `CAP_BPF` / root for `-tags with_ebpf`. Otherwise auditd → `/proc` poll.
- **Recommended:** **root** for full `/proc` visibility (see [Privileges](#privileges)).

---

## Build

Default build (pure Go, no cgo — macOS OK for compile/test):

```bash
git clone https://github.com/sercanokur/GhostCatcherEDR.git
cd GhostCatcherEDR
go build -o ghostcatcher ./cmd/agent
```

Optional tags:

```bash
CGO_ENABLED=1 go build -tags with_yara -o ghostcatcher ./cmd/agent
go build -tags with_ebpf -o ghostcatcher ./cmd/agent
CGO_ENABLED=1 go build -tags "with_yara with_ebpf" -o ghostcatcher ./cmd/agent
```

Tests and detection-quality gate:

```bash
go test ./...
go run ./cmd/agent eval -corpus testdata/eval -min-f1 0.85
```

Lab UI (optional): `go run ./cmd/demo-console` — local kill-chain demo console, not part of the agent binary.

---

## Continuous integration

[![CI](https://github.com/sercanokur/GhostCatcherEDR/actions/workflows/ci.yml/badge.svg)](https://github.com/sercanokur/GhostCatcherEDR/actions/workflows/ci.yml)

On **push** to `main` and on **pull requests**, [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs:

- `go build ./...`, `go vet ./...`, `go test -race -covermode=atomic ./...`
- `go run ./cmd/agent eval -corpus testdata/eval -min-f1 0.85`
- **[golangci-lint](https://golangci-lint.run/)** v2 (config: [`.golangci.yml`](.golangci.yml))
- **[gosec](https://github.com/securego/gosec)** (EDR-oriented excludes for path walks / dpkg MD5 / etc.; demo-console skipped)
- **[govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)**
- **[syft](https://github.com/anchore/syft)** CycloneDX SBOM artifact
- On **version tags** (`v*`): **[cosign](https://github.com/sigstore/cosign)** keyless signing of the release binary

---

## Quick start

1. Copy and edit config:

   ```bash
   cp configs/config.example.yaml configs/config.yaml
   # Set document_roots, baseline_path, rule_pack_path, mapping_path, watched_units.
   ```

2. Validate:

   ```bash
   ./ghostcatcher check-config -config configs/config.yaml
   ```

3. First baseline (trusted host state):

   ```bash
   sudo ./ghostcatcher baseline commit -config configs/config.yaml
   ```

4. One-shot scan:

   ```bash
   sudo ./ghostcatcher run -config configs/config.yaml -once
   ```

5. Continuous run (interval + sensor + fsnotify):

   ```bash
   sudo ./ghostcatcher run -config configs/config.yaml
   ```

6. Eval harness:

   ```bash
   ./ghostcatcher eval -corpus testdata/eval -min-f1 0.85
   ```

Example unit: [`systemd/ghostcatcher.service`](systemd/ghostcatcher.service). Use `Type=notify` and `WatchdogSec=` if you enable the self-guard watchdog.

---

## Install on a server (production)

Typical Ubuntu/Debian layout:

| Path | Purpose |
|------|---------|
| `/usr/local/bin/ghostcatcher` | Binary |
| `/etc/ghostcatcher/config.yaml` | Main config |
| `/etc/ghostcatcher/rule_pack.yaml` | Rule pack (from `rule_pack.example.yaml` or lab pack) |
| `/etc/ghostcatcher/mapping.yaml` | Behavior catalog (from `configs/mapping.yaml`) |
| `/var/lib/ghostcatcher/` | State (`baseline.json`, spool, quarantine) |

**Steps**

1. Build for `linux/amd64` (or arm64), then:

   ```bash
   sudo install -m 0755 ghostcatcher /usr/local/bin/ghostcatcher
   ```

2. Install configs:

   ```bash
   sudo mkdir -p /etc/ghostcatcher /var/lib/ghostcatcher
   sudo cp configs/config.example.yaml /etc/ghostcatcher/config.yaml
   sudo cp configs/rule_pack.example.yaml /etc/ghostcatcher/rule_pack.yaml
   sudo cp configs/mapping.yaml /etc/ghostcatcher/mapping.yaml
   sudo chmod 0640 /etc/ghostcatcher/*.yaml
   ```

3. Edit `/etc/ghostcatcher/config.yaml` — at least:

   - `baseline_path` → `/var/lib/ghostcatcher/baseline.json`
   - `rule_pack_path` → `/etc/ghostcatcher/rule_pack.yaml`
   - `mapping_path` → `/etc/ghostcatcher/mapping.yaml`
   - `document_roots`, `watched_units`
   - sinks as needed

4. Validate → baseline → enable systemd (same flow as before). See [Configuration checklist](#configuration-checklist).

5. Logs: JSON events on **stdout** (journald); ops messages on **stderr**. `journalctl -u ghostcatcher -f`.

---

## Configuration checklist

### Must set

| Setting | Why |
|---------|-----|
| `document_roots` | Web roots to scan; empty = missed M1 coverage. |
| `baseline_path` | Persistent deltas after `baseline commit`. |
| `rule_pack_path` | Scoring / expressions / responses. |
| `mapping_path` | Taxonomy + CHAIN-1…6 (defaults to `./configs/mapping.yaml` if empty). |
| `watched_units` | Primary web/worker anchors (e.g. `nginx.service`, `php8.3-fpm.service`). |

### Strongly recommended

| Setting | Why |
|---------|-----|
| `fp_allowlist_units` | Suppress FIM/inventory noise from apt/snap/logrotate-style units. |
| `scan_interval` | Latency vs load. |
| `min_confidence_for_alert` | Noise floor (default `70`). |
| `path_allowlist_prefixes` / `ld_preload_allowlist` / `network_allow_cidrs` | Estate-specific FP control. |
| Sink blocks | `syslog_udp` / `syslog_tcp` / `splunk_hec` / `elastic_bulk` / `loki_push`. |
| `require_root: true` | Fail fast without full `/proc`. |
| Rule-pack signature files | Refuse tampered packs. |
| `selfguard.*` | Agent integrity + systemd watchdog. |

### Optional

| Setting | When |
|---------|------|
| `maps_scan_enabled` | Fileless / inject heuristics on Linux web hosts. |
| `integrity_verify_enabled` | Package hash verification. |
| `copy_fail.*` | CVE-2026-31431 legs. |
| `respond.*` | OODA Act policy (default `mode: audit` / alert-only). |
| `sigma_lite_dir` / `yara_*` / `ioc_feed_dir` | Extra detectors. |
| `quarantine_*` / `spool_*` / `rate_limit_*` | Evidence + backpressure. |
| `baseline_commit_token_env` | 2FA for baseline overwrite. |
| `learning_mode` / `first_run_allow_alerts` | Pilot workflow. |

After changes: `check-config` then restart the unit.

---

## SIEM integration (syslog / HEC / bulk / Loki)

The same schema **1.3** JSON event goes to stdout and every enabled sink. Sink failures append to the on-disk spool.

| Sink | Config block | Transport |
|------|--------------|-----------|
| UDP syslog | `syslog_udp` | UDP RFC5424 / RFC3164 + JSON MSG |
| TCP / TLS syslog | `syslog_tcp` | RFC5425 frames |
| Splunk HEC | `splunk_hec` | HTTPS collector |
| Elasticsearch | `elastic_bulk` | HTTPS `_bulk` |
| Grafana Loki | `loki_push` | HTTPS push API |

Examples live in [`configs/config.example.yaml`](configs/config.example.yaml). Parse syslog **MSG** as JSON; HEC/Elastic/Loki bodies are already JSON. Prefer TCP/TLS or HTTPS for large events.

Without a sink: ship journald / stdout JSONL with any log agent—the payload schema is identical.

---

## Stop or disable the service

```bash
sudo systemctl stop ghostcatcher.service
sudo systemctl disable --now ghostcatcher.service
# optional: sudo systemctl mask ghostcatcher.service
```

Foreground runs: **Ctrl+C**. Config and baseline remain on disk until you delete `/etc/ghostcatcher/` and `/var/lib/ghostcatcher/`.

---

## Configuration

All keys: [`configs/config.example.yaml`](configs/config.example.yaml). Important additions vs older installs:

| Key | Purpose |
|-----|---------|
| `mapping_path` | Nano catalog + chains. |
| `watched_units` / `fp_allowlist_units` | Anchor selection and FP units. |
| `copy_fail` / `sudden_root` | Copy Fail CVE legs; sudden-root tracker. |
| `respond` | Active-response policy (OODA Act). |
| `syslog_*` / `splunk_hec` / `elastic_bulk` / `loki_push` | Sinks. |
| `selfguard` / `quarantine_*` / `spool_*` / `sigma_lite_dir` / `yara_*` / `ioc_feed_dir` | Hardening and extras. |

Wiki: [Configuration](docs/wiki/Configuration.md).

---

## Rule pack

Versioned YAML: per-rule `id` (nano), `techniques`, scoring, optional `expr`, `correlate` / `correlate_window` / `correlate_boost`, optional `response`, optional taxonomy fields.

```
signal("WEB_SHELL_PATTERN") and confidence >= 70
comm in ["sh","bash","nc"] and not parent_comm in ["systemd","init"]
matches(entity_path, "^/tmp/.*\\.so$")
```

Sign with ed25519 (fail closed when pubkey + signature paths are set):

```bash
openssl genpkey -algorithm Ed25519 -out rulepack.key
openssl pkey -in rulepack.key -pubout -outform DER \
  | tail -c 32 | base64 > /etc/ghostcatcher/rulepack.pub
openssl pkeyutl -sign -inkey rulepack.key \
  -in /etc/ghostcatcher/rule_pack.yaml \
  -out /etc/ghostcatcher/rule_pack.yaml.sig
```

---

## Output format

One JSON object per detection on **stdout** (and sinks). Schema **1.3**:

- Identity: `schema_version`, `agent_version`, `rule_pack_version`, `timestamp`, `rule_id`, `technique_id`, `tactic`, `severity`, `confidence`, `correlation_id`, `learning_only`, `dedup_key`.
- Taxonomy: `macro`, `micro`, `src`, `type`, `anchor`, `conf_band`, `chain_id`, `evidence_loss`.
- Doctrine (1.2+): `kill_chain_phase`, `defense_layer`, `soc_escalate`, `response` when set.
- Entity + context: `entity`, `process`, `file`, `network`, `container`.
- Matching: `signals[]`, `evidence`, `ioc_matches[]`.

```bash
sudo ./ghostcatcher run -config configs/config.yaml -once | jq .
```

Ops messages use **stderr**.

---

## Privileges

- **Root:** other users’ keys, all PIDs’ environ/maps/fd, `/proc/net`↔inode, kmods, system cron/systemd; required for eBPF attach.
- **Non-root:** partial visibility; many checks degrade.
- **Integrity:** needs `/var/lib/dpkg` or `rpm`; skipped otherwise.

---

## Project layout

```
.
├── bhv.md                 # Human-readable Macro→Micro→Nano doctrine
├── cmd/
│   ├── agent/             # CLI: run | baseline | check-config | eval
│   └── demo-console/      # Optional lab kill-chain UI
├── configs/
│   ├── config.example.yaml
│   ├── mapping.yaml       # Taxonomy + CHAIN-1…6
│   ├── rule_pack.example.yaml
│   └── lab_rule_pack.yaml
├── docs/wiki/             # GitHub Wiki source
├── .github/workflows/     # CI
├── internal/
│   ├── anchor/            # cgroup → systemd unit
│   ├── attack/            # ATT&CK navigator helpers
│   ├── baseline/
│   ├── config/
│   ├── container/
│   ├── detect/
│   │   ├── web/ ancestry/ network/
│   │   ├── persistence/ fimextra/
│   │   ├── ldpreload/ integrity/ defense/ privesc/ copyfail/
│   │   ├── memorymaps/ sensorlive/
│   │   ├── credential/ containeresc/
│   │   └── yara/
│   ├── emit/ eval/ event/   # schema 1.3
│   ├── export/{syslog,syslogtcp,splunk,elastic,loki}/
│   ├── ioc/ killchain/ procfs/
│   ├── quarantine/ respond/ rules/ runner/
│   ├── selfguard/ sensor/ taxonomy/ watch/
├── systemd/
└── testdata/{web,eval}/
```

---

## Limitations

- Not a substitute for enterprise EDR, managed hunting, or kernel enforcement.
- eBPF needs kernel ≥ 5.8 + `CAP_BPF`; else auditd / `/proc` with less fidelity.
- YARA needs `-tags with_yara` + libyara; default stub matches nothing.
- Host-visible sockets only—no out-of-host netflow.
- Heuristics false-positive; use baselines, allowlists, `fp_allowlist_units`, and confidence floors.
- Signed packs and self-guard help at rest/load; a live root adversary can still interfere.

---

## Contributing

Issues and PRs welcome (docs, tests, detectors, sinks).

Before a PR: `go test ./...`, `go vet ./...`, `golangci-lint run` (or rely on CI), and `check-config` with your sample YAML. Keep wiki pages under `docs/wiki/` in sync when you change schema or nanos.

---

## License

[MIT License](LICENSE).

---

## Security

Report vulnerabilities per [`SECURITY.md`](SECURITY.md). Do not open public issues for undisclosed exploitable bugs until coordinated disclosure is complete.
