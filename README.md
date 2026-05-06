# GhostCatcher (endpoint agent)

A **Linux endpoint** detection agent written in **Go**. It runs as a CLI or **systemd** service, scans the host on an interval, streams from a runtime-selected **eBPF / auditd / /proc** sensor, watches sensitive paths via **fsnotify**, and emits **one JSON object per line** on stdout plus any configured enterprise sinks (UDP/TCP/TLS syslog, Splunk HEC, Elastic `_bulk`, Grafana Loki).

GhostCatcher targets **host-visible** behaviors aligned with common intrusion patterns — web shells, `LD_PRELOAD` hijacking, SSH/cron/systemd persistence, PAM/sudoers tampering, SUID / file-capability drift, reverse shells, reflective loading — using **baselines**, **multi-signal scoring**, a **signed rule pack** (ed25519), **time-windowed correlation**, **CEL-style boolean expressions**, **Sigma-lite** rule drop-ins, **YARA** (optional cgo build tag), a **PHP taint-flow mini-parser**, **IOC feeds**, and **container context**.

> **Scope:** No kernel driver, no TLS inspection, no managed cloud backend. Runs as a single statically-linkable binary; cgo dependencies (YARA, eBPF) live behind build tags.

---

## Mission

Advanced **APT** groups increasingly treat Linux as a first-class target: the same strategic idea as *living off the land* on other platforms—abuse **built-in tools, legitimate services, and normal administration paths** so activity blends into operations. Linux often underpins **databases, web front ends, and cloud- and platform-control planes**, so for these actors the recurring priorities are **long-lived persistence** (quiet footholds that survive patches and reboots) and **low-noise collection or exfiltration** that does not depend on noisy malware families.

GhostCatcher exists to **shorten the window** where those behaviors go unseen on the host: web-layer backdoors, preload-based evasion, stolen trust in `authorized_keys` and job schedulers, and related local signals that **IDS** or perimeter tools may only infer indirectly. It is an **open, inspectable** layer teams can tune to their estate and feed into a SIEM—**complementary** to IDS, EDR-class stacks, and hunting programs, not a substitute for depth across the full kill chain.

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

### Detection surface

| Area | Mechanism |
|------|-----------|
| **Web shell / PHP-style patterns** | 30+ regex patterns over PHP / JSP / ASPX / ColdFusion / Perl, run after a normalization pass (comment strip, `"ev"."al"` concat collapse, recursive inline base64 decode). Corroborating signals: **Shannon entropy**, **magic-byte / polyglot mismatch**, **SUID/SGID** and `www-data`/`apache` ownership, tiny-high-signal heuristic. |
| **PHP taint flow** | Intraprocedural tokenizer that tracks assignments from `$_GET` / `$_POST` / `$_REQUEST` / `$_COOKIE` / `$_SERVER` / `php://input` into dangerous sinks (`eval`, `assert`, `system`, `exec`, `shell_exec`, `proc_open`, `preg_replace`/e, `include` …). |
| **Recon children under web workers** | Flags `whoami`, `ifconfig`, `uname`, `id`, `curl`, etc. spawned beneath `nginx` / `apache2` / `php-fpm` / `tomcat`. |
| **Fileless / memory hints** | `/proc/[pid]/maps`: RWX-backed regions with `/dev/shm`/`/tmp` paths, `(deleted)` execution segments, `TracerPid` drift, `CapEff` escalation, and **per-process shared object allowlist** baselined at commit. |
| **`LD_PRELOAD` / preload file** | `/etc/ld.so.preload` and `LD_PRELOAD` in `/proc/[pid]/environ`; allowlists in config. |
| **SSH persistence** | `~/.ssh/authorized_keys` fingerprint delta, invalid-line anomaly, `sshd_config` / `sshd_config.d` delta (`PermitRootLogin`, `AuthorizedKeysCommand`, `ForceCommand`). |
| **Cron persistence** | `/etc/crontab`, `/etc/cron.{hourly,daily,weekly,monthly,d}`, `/etc/anacrontab`, `/var/spool/cron/…`, `/var/spool/atjobs`. Tokens normalized (quote-stripping shlex) and **base64 payloads recursively decoded** before risk match (`curl`, `bash -c`, `/dev/tcp/`, `nc`, `base64 -d`, …). |
| **systemd persistence** | New / changed `*.service` / `*.timer` units; flags risky `ExecStart*` + `User=root` combinations. |
| **Shell / profile / PAM / sudoers** | `~/.bashrc` / `~/.zshrc` / `/etc/profile` delta + high-risk tokens; `/etc/pam.d/*` and module refs (`pam_exec.so`, `pam_python.so`); `/etc/sudoers` + `/etc/sudoers.d/*` dangerous directives. |
| **Users** | `/etc/passwd` / `/etc/shadow`: UID 0 non-root accounts, newly added accounts, empty password hashes. |
| **Kernel modules** | `/proc/modules` delta + `/etc/modules-load.d`, `/etc/modprobe.d` drop-in changes. |
| **Dynamic linker** | `ld.so.conf` and `ld.so.conf.d` modifications, especially world-writable additions. |
| **Binary integrity (Debian/Ubuntu + RHEL/CentOS/Fedora)** | Auto-dispatch via `/etc/os-release`: **dpkg md5sums** or **`rpm -Va`** for watched critical paths; TOCTOU-safe (fd-pinned hashing). |
| **SUID / capabilities drift** | Walks `$PATH`-like dirs; alerts on new SUID/SGID binaries, hash changes, world-writable path SUID, and changes in `security.capability` xattr. |
| **Process ancestry (`PROC_RARE_ANCESTRY`)** | Flags unseen `(parent_comm, child_comm)` pairs where the parent is juicy (`nginx`, `sshd`, `mysqld`, `cron`, …) and the child is `sh`/`bash`/`nc`/`curl`/etc. Baselined at commit. |
| **Network sensor** | `/proc/net/tcp[6]` + `/proc/net/udp[6]` correlated with `/proc/*/fd` inodes to detect **reverse shells** (shell-like outbound to public IPs), **unexpected listens**, and **web worker egress**; CIDR allowlist-driven. |
| **Real-time watchers** | `fsnotify` on `authorized_keys`, `ld.so.preload`, crontab + `cron.d`, systemd unit dirs, `sudoers.d`, `pam.d`, `sshd_config.d`, `document_roots` (recursive), `passwd`, `shadow` — debounced rescan on change. |
| **Exec sensor** | Runtime-selected backend: **eBPF** (`-tags with_ebpf`, cilium/ebpf; exec/openat/connect/ptrace/init_module/memfd) → **auditd** tail (`/var/log/audit/audit.log`, no libaudit dependency) → **/proc poll** fallback. |
| **YARA** | Optional `-tags with_yara` build (hillu/go-yara/v4): disk scan across document roots **and** live process memory for watched comms. |
| **IOC feed weighting** | Flat-file hash / IP / CIDR / domain feeds cross-referenced at emit; network IOC hits add +25 confidence, file-hash hits +10. |
| **Container context** | Classifies Docker / containerd / cri-o / k8s / lxc IDs and Pod UIDs from `/proc/[pid]/cgroup`. |
| **CVE-2026-31431 ("Copy Fail")** | Two-leg coverage in `internal/detect/copyfail`: (1) live AF_ALG `SOCK_SEQPACKET` `socket()` syscalls observed by the auditd / eBPF sensor and routed through the detector when the calling `comm` is outside a small disk-encryption / kTLS allowlist (`cryptsetup`, `systemd-cryptse`, `veritysetup`, `kcapi-*`); (2) periodic page-cache vs on-disk hash drift on watched SUID binaries (`/usr/bin/su`, `sudo`, `passwd`, `mount`, …) using `posix_fadvise(POSIX_FADV_DONTNEED)` to bypass the page cache. The page-cache leg catches the actual exploit's effect — corrupted cached pages of a `setuid` root binary that still hashes "clean" on disk. |

### Engine

| Area | Mechanism |
|------|-----------|
| **Rule engine v2** | Each rule may carry a boolean **CEL-style expression** (`signal("…") and confidence >= 70`, `comm in ["sh","bash"]`, `matches(entity_path, "^/tmp/.*\\.so$")`, `contains`, `not`, `and/or`). An expression that returns false downgrades the event to `learning_only` instead of alerting. |
| **Time-windowed correlation** | Rules declare `correlate:` peers + `correlate_window`; events on the same entity within the window get a configurable confidence boost and a `correlation_boost` signal. |
| **Sigma-lite loader** | Drop `*.yml` Sigma files under `sigma_lite_dir`; a subset (`selection` + `condition: selection`, `contains` / `endswith` / `startswith` / `re`) is transpiled into native expressions at load. |
| **Signed rule packs** | Optional ed25519 detached signature (`rule_pack_pubkey_file` + `rule_pack_signature_file`); load fails closed on mismatch. |
| **Rate limiter + on-disk spool** | Per-rule sliding-window cap (`rate_limit_per_rule_per_min`) + newline-delimited JSON spool for sinks that are temporarily unreachable; auto-rotates at `spool_max_bytes`. |
| **Quarantine vault** | High-confidence file artifacts copied to `<vault>/<YYYYMMDD>/<sha256>.bin` (mode 0400) with a sidecar JSON (rule, signals, original mode / mtime / owner). |
| **Self-guard** | Periodic sha256 check of the agent binary (`AGENT_TAMPERED` critical event on drift) + systemd `WATCHDOG=1` notifications using `WATCHDOG_USEC`. |
| **Baseline commit 2FA** | Optional token read from `baseline_commit_token_env`; `baseline commit -token <value>` must match before overwrite. |

### Sinks

| Transport | Notes |
|-----------|-------|
| stdout JSONL | Always enabled. |
| **UDP syslog** | RFC5424 or RFC3164, configurable facility / PRI. |
| **TCP / TLS syslog** | RFC5425 octet-framed; optional CA cert + SNI; single-retry on transport error. |
| **Splunk HEC** | POST `{"event": …}` with `sourcetype` / `index`. |
| **Elasticsearch `_bulk`** | NDJSON upload, API key or basic auth. |
| **Grafana Loki** | `/loki/api/v1/push` with static + per-event labels (`rule_id`, `severity`). |

All sinks implement a common `Sink` interface; any failure routes the raw JSON line into the spool.

Baseline is stored as JSON (`baseline commit`). Alerts respect **`min_confidence_for_alert`** and **`learning_mode`** until you freeze a baseline.

---

## What it detects (summary)

Rules are defined in the YAML **rule pack**; each emitted event includes `technique_id` (MITRE-style IDs) and `rule_id`. Shipped rules cover:

- **T1505.003** / **T1059.004** / **T1059.006** — web shells, worker children, recon argv, reverse shell spawns.
- **T1574.006** / **T1014** — `LD_PRELOAD`, `ld.so.preload`, rootkit-style kernel modules.
- **T1098.004** / **T1136.001** — new authorized key fingerprints, new local users, UID-0 accounts.
- **T1053.003** / **T1053.006** — cron + systemd timer deltas with decoded base64 payloads.
- **T1055** / **T1055.001** / **T1620** — RWX mappings, `(deleted)` execution segments, reflective loads.
- **T1036** — md5 / rpm mismatch for watched binaries.
- **T1556.003** / **T1548.003** — PAM modules, sudoers escalation paths.
- **T1562.001** — tampering of agent binary (`AGENT_TAMPERED`).
- **T1571** / **T1041** / **T1071.001** — unexpected listens, web worker egress, reverse-shell outbound.
- **T1068** / **T1014** — CVE-2026-31431 ("Copy Fail") AF_ALG AEAD socket creation by an untrusted process (`CVE_2026_31431_AF_ALG_AEAD`) and SUID-binary page-cache poisoning (`CVE_2026_31431_PAGE_CACHE_POISONING`).

Exact scoring, `min_signals`, correlation windows and boolean expressions per rule are in [`configs/rule_pack.example.yaml`](configs/rule_pack.example.yaml).

---

## Requirements

- **Go** 1.22 or newer (see [`go.mod`](go.mod)).
- **Runtime:** Linux. Integrity backends auto-select between `dpkg` (Debian/Ubuntu) and `rpm` (RHEL/CentOS/Fedora) based on `/etc/os-release`.
- **Optional (cgo):** [YARA ≥ 4.3](https://virustotal.github.io/yara/) headers + libs to enable `-tags with_yara`.
- **Optional (kernel):** Linux ≥ 5.8 with `CONFIG_BPF_SYSCALL=y` and `CAP_BPF` / root to enable `-tags with_ebpf`. Falls back to `auditd` then `/proc` polling when unavailable.
- **Recommended:** run as **root** for full `/proc` visibility across users and PIDs (see [Privileges](#privileges)).

---

## Build

Default build (pure Go, no cgo, no kernel dependencies — works on macOS too for testing):

```bash
git clone https://github.com/sercanokur/GhostCatcherEDR.git
cd GhostCatcherEntpointDetection
go build -o ghostcatcher ./cmd/agent
```

Optional build tags (combinable):

```bash
# YARA disk + memory scanner (requires libyara headers)
CGO_ENABLED=1 go build -tags with_yara -o ghostcatcher ./cmd/agent

# eBPF exec / openat / connect / ptrace / init_module / memfd sensor
go build -tags with_ebpf -o ghostcatcher ./cmd/agent

# Both
CGO_ENABLED=1 go build -tags "with_yara with_ebpf" -o ghostcatcher ./cmd/agent
```

Run tests and the detection-quality harness:

```bash
go test ./...
go run ./cmd/agent eval -corpus testdata/eval -min-f1 0.85
```

---

## Continuous integration

[![CI](https://github.com/sercanokur/GhostCatcherEDR/actions/workflows/ci.yml/badge.svg)](https://github.com/sercanokur/GhostCatcherEDR/actions/workflows/ci.yml)

On every **push** and **pull request** to `main` / `master` (and on tag pushes for releases), [GitHub Actions](.github/workflows/ci.yml) runs:

- `go mod verify`, `go build`, `go vet ./...`, `go test -race ./...`
- `ghostcatcher check-config` against [`configs/config.example.yaml`](configs/config.example.yaml)
- `ghostcatcher eval -corpus testdata/eval -min-f1 0.85` — fails the build if detection precision/recall regresses below the configured F1 threshold
- **[golangci-lint](https://golangci-lint.run/)** driven by [`.golangci.yml`](.golangci.yml)
- **[gosec](https://github.com/securego/gosec)** static analysis
- **[govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)** vulnerability database
- **[syft](https://github.com/anchore/syft)** — SPDX SBOM uploaded as a CI artifact
- **[cosign](https://github.com/sigstore/cosign)** blob signing of release binaries on tag pushes (keyless OIDC)

---

## Quick start

1. Copy and edit config:

   ```bash
   cp configs/config.example.yaml configs/config.yaml
   # Set document_roots, baseline_path, rule_pack_path for your host.
   ```

2. Validate config and rule pack:

   ```bash
   ./ghostcatcher check-config -config configs/config.yaml
   ```

3. **First baseline** (after you trust the current host state):

   ```bash
   sudo ./ghostcatcher baseline commit -config configs/config.yaml
   ```

4. Run a single scan:

   ```bash
   sudo ./ghostcatcher run -config configs/config.yaml -once
   ```

5. Run continuously (interval from `scan_interval`; also starts the realtime sensor and fsnotify watchers):

   ```bash
   sudo ./ghostcatcher run -config configs/config.yaml
   ```

6. Regression-test your rule pack against the shipped (or your own) labeled corpus:

   ```bash
   ./ghostcatcher eval -corpus testdata/eval -min-f1 0.85
   ```

Example **systemd** unit: [`systemd/ghostcatcher.service`](systemd/ghostcatcher.service). Set `Type=notify` and a `WatchdogSec=` on the unit if you want the `selfguard` watchdog loop to keep the service alive.

---

## Install on a server (production)

Typical layout on Ubuntu/Debian:

| Path | Purpose |
|------|---------|
| `/usr/local/bin/ghostcatcher` | Binary |
| `/etc/ghostcatcher/config.yaml` | Main YAML config |
| `/etc/ghostcatcher/rule_pack.yaml` | Rule pack (copy from `configs/rule_pack.example.yaml` and tune if needed) |
| `/var/lib/ghostcatcher/` | State directory (`baseline.json` via `baseline_path`) |

**Steps**

1. **Build** on a build host (or cross-compile for `linux/amd64`), then install the binary:

   ```bash
   sudo install -m 0755 ghostcatcher /usr/local/bin/ghostcatcher
   ```

2. **Create directories and copy configs:**

   ```bash
   sudo mkdir -p /etc/ghostcatcher /var/lib/ghostcatcher
   sudo cp configs/config.example.yaml /etc/ghostcatcher/config.yaml
   sudo cp configs/rule_pack.example.yaml /etc/ghostcatcher/rule_pack.yaml
   sudo chmod 0640 /etc/ghostcatcher/config.yaml /etc/ghostcatcher/rule_pack.yaml
   ```

3. **Edit** `/etc/ghostcatcher/config.yaml` (see [Configuration checklist](#configuration-checklist)). Set at least:

   - `baseline_path` → e.g. `/var/lib/ghostcatcher/baseline.json`
   - `rule_pack_path` → `/etc/ghostcatcher/rule_pack.yaml`
   - `document_roots` → real web roots on this host
   - `syslog_udp` if you ingest via SIEM

4. **Validate:**

   ```bash
   sudo ghostcatcher check-config -config /etc/ghostcatcher/config.yaml
   ```

5. **Baseline** when the host is in a known-good state:

   ```bash
   sudo ghostcatcher baseline commit -config /etc/ghostcatcher/config.yaml
   ```

6. **systemd** — adjust [`systemd/ghostcatcher.service`](systemd/ghostcatcher.service) if your paths differ, then:

   ```bash
   sudo cp systemd/ghostcatcher.service /etc/systemd/system/ghostcatcher.service
   sudo systemctl daemon-reload
   sudo systemctl enable ghostcatcher.service
   sudo systemctl start ghostcatcher.service
   sudo systemctl status ghostcatcher.service
   ```

7. **Logs** — by default JSON events go to **stdout** (journald captures them). Use `journalctl -u ghostcatcher -f` to view. Operational messages from the agent go to **stderr**.

---

## Configuration checklist

Customize these for **your** server and SOC workflow:

### Must set (almost every deployment)

| Setting | Why |
|---------|-----|
| `document_roots` | List every web root (nginx/Apache `root` / `DocumentRoot`) you want scanned for PHP/JSP. Wrong or empty paths = missed web-shell coverage. |
| `baseline_path` | Persistent path (e.g. under `/var/lib/ghostcatcher/`). Required for stable deltas after `baseline commit`. |
| `rule_pack_path` | Point to the YAML you ship (e.g. `/etc/ghostcatcher/rule_pack.yaml`). |

### Strongly recommended

| Setting | Why |
|---------|-----|
| `scan_interval` | Balance CPU/load vs detection latency (e.g. `5m` production, `1m` aggressive). |
| `min_confidence_for_alert` | Tune noise vs signal with your rule pack (default `70`; raise if too chatty). |
| `path_allowlist_prefixes` | Exclude vendor/CMS trees that trigger PHP heuristics (`vendor/`, framework caches). |
| `ld_preload_allowlist` | Add legitimate `LD_PRELOAD` fragments if you use profiling or security wrappers. |
| `syslog_udp` / `syslog_tcp` / `splunk_hec` / `elastic_bulk` / `loki_push` | Enable one or more sink blocks so events reach your SIEM. |
| `require_root: true` | Enforces root so the agent fails fast if started without full `/proc` coverage. |
| `rule_pack_pubkey_file` + `rule_pack_signature_file` | Refuse to load an unsigned / tampered rule pack in production. |
| `selfguard.binary_path` + `selfguard.expected_sha256` | Turn on agent self-integrity; pair with `Type=notify` + `WatchdogSec=` in the unit file. |

### Optional / environment-specific

| Setting | When |
|---------|------|
| `maps_scan_enabled` | Linux web servers; expect possible false positives—use `maps_path_allowlist_prefixes` after testing. |
| `integrity_verify_enabled` | Auto-dispatches to `dpkg` or `rpm` from `/etc/os-release`; silently skipped on other distros. |
| `watch_authorized_keys` | Faster reaction to `authorized_keys` edits; needs readable `.ssh` dirs. |
| `learning_mode` | `true` during pilot; set `false` once baselines and thresholds are trusted. |
| `first_run_allow_alerts` | Usually `false`; only if you explicitly want higher-severity alerts before the first `baseline commit`. |
| `sigma_lite_dir` | Drop Sigma YAML files for external detections alongside the native rule pack. |
| `yara_rules_dir` + `yara_memory_enabled` | Only honored when built with `-tags with_yara`. |
| `ancestry_scan_enabled` | Enables `PROC_RARE_ANCESTRY` detection against the baselined process graph. |
| `ioc_feed_dir` | Flat-file hash / IP / CIDR / domain lists to weight confidence on match. |
| `quarantine_dir` + `quarantine_min_confidence` | Stores copies of high-confidence file artifacts with a metadata sidecar. |
| `rate_limit_per_rule_per_min` + `spool_dir` + `spool_max_bytes` | Bound per-rule emit rate and buffer events when sinks are unreachable. |
| `baseline_commit_token_env` | Turn on 2FA for `baseline commit`; the CLI requires `-token $VAR`. |

After any change: `sudo ghostcatcher check-config -config /etc/ghostcatcher/config.yaml` then `sudo systemctl restart ghostcatcher` (if using systemd).

---

## SIEM integration (syslog / HEC / bulk / Loki)

The agent can emit **the same JSON event** to **stdout** and to any combination of enterprise sinks. All sinks are opt-in and independent; if a sink fails, the raw JSON line is appended to the on-disk spool and retried on the next successful write.

### Sink summary

| Sink | Config block | Transport | Payload |
|------|--------------|-----------|---------|
| UDP syslog | `syslog_udp` | UDP | RFC5424 / RFC3164 header + JSON in MSG |
| TCP / TLS syslog | `syslog_tcp` | TCP, optional TLS | RFC5425 octet-counted frames |
| Splunk HEC | `splunk_hec` | HTTPS | `POST /services/collector`, `{"event": …, "sourcetype", "index"}` |
| Elasticsearch | `elastic_bulk` | HTTPS | `POST /_bulk` NDJSON, configurable `index` |
| Grafana Loki | `loki_push` | HTTPS | `POST /loki/api/v1/push` with static + per-event labels |

### Example UDP syslog block

```yaml
syslog_udp:
  enabled: true
  host: siem-collector.internal
  port: 5514
  format: rfc5424
  facility: local0
  app_name: ghostcatcher
  hostname: web-prod-01
  max_msg_bytes: 8192
```

### Example TCP/TLS syslog block

```yaml
syslog_tcp:
  enabled: true
  address: siem-collector.internal:6514
  tls: true
  ca_file: /etc/ghostcatcher/ca.pem
  server_name: siem-collector.internal
  app_name: ghostcatcher
```

### Example Splunk HEC / Elastic / Loki blocks

```yaml
splunk_hec:
  enabled: true
  url: https://splunk.internal:8088/services/collector
  token: "${SPLUNK_HEC_TOKEN}"
  sourcetype: ghostcatcher:event
  index: security

elastic_bulk:
  enabled: true
  url: https://es.internal:9200
  index: ghostcatcher-events
  api_key: "${ES_API_KEY}"

loki_push:
  enabled: true
  url: https://loki.internal/loki/api/v1/push
  tenant_id: security
  static_labels:
    job: ghostcatcher
    env: prod
```

### Collector-side checklist

1. Pick one or more sinks above and open the matching ingress on your SIEM / relay.
2. For syslog, parse the **MSG** field as JSON (after the RFC5424/5425 header).
3. For HEC / Elastic / Loki the body is already JSON; no extra parser needed.
4. Raise **`max_msg_bytes`** if events are truncated; UDP is capped by MTU, prefer TCP/TLS or HTTPS sinks for large events.

### If you do not use any sink

Point **journald** or a log shipper at the service stdout (JSON lines) and parse JSON there — the payload schema is the same as in every sink body.

---

## Stop or disable the service

### systemd (recommended)

```bash
# Stop now (does not disable boot start)
sudo systemctl stop ghostcatcher.service

# Stop and disable future starts
sudo systemctl disable --now ghostcatcher.service

# Optional: prevent any start until unmasked
sudo systemctl mask ghostcatcher.service
# Undo mask later:
# sudo systemctl unmask ghostcatcher.service
```

Check it is inactive:

```bash
sudo systemctl status ghostcatcher.service
```

### Foreground / manual `run`

If you started the agent manually in a terminal:

- Press **Ctrl+C** (SIGINT) to exit the loop.
- Or from another shell: `sudo pkill -f 'ghostcatcher run'` (use with care on shared hosts; prefer matching the full command line).

### After stopping

- Config and **baseline** files remain on disk; scans simply no longer run.
- To remove the software: stop/disable the unit, delete `/usr/local/bin/ghostcatcher`, and remove `/etc/ghostcatcher/` and optionally `/var/lib/ghostcatcher/` if you no longer need the baseline.

---

## Configuration

Main options live in YAML. See [`configs/config.example.yaml`](configs/config.example.yaml) for all keys, including:

| Key | Purpose |
|-----|---------|
| `scan_interval` | Ticker period for `run` (not `-once`). |
| `document_roots` | Web roots to walk for `.php` / `.jsp` / `.jspx` / `.aspx` / `.ashx` / `.phar` / `.cfm` / `.inc`. |
| `baseline_path` | JSON snapshot path. |
| `rule_pack_path` | YAML rules + expressions + correlation metadata. |
| `rule_pack_pubkey_file` / `rule_pack_signature_file` | ed25519 detached signature verification. |
| `sigma_lite_dir` | Directory of Sigma-lite `*.yml` drop-ins merged into the rule pack. |
| `min_confidence_for_alert` | Minimum `confidence` to treat as production alert (still emitted as JSON; `learning_only` may apply). |
| `learning_mode` / `first_run_allow_alerts` | Learning workflow toggles. |
| `require_root` | Exit if not UID 0 when true. |
| `maps_scan_enabled` / `maps_watch_processes` / `maps_path_allowlist_prefixes` | `/proc/maps` heuristics. |
| `integrity_verify_enabled` / `integrity_paths` | `dpkg` / `rpm` verification with auto-dispatch. |
| `web_recon_child_scan_enabled` | Recon argv under web workers. |
| `watch_authorized_keys` | Enables fsnotify watchers for sensitive paths. |
| `ancestry_scan_enabled` | Emits `PROC_RARE_ANCESTRY` events. |
| `yara_rules_dir` / `yara_memory_enabled` | Honored only with `-tags with_yara`. |
| `ioc_feed_dir` | Flat files with hash / IP / CIDR / domain indicators. |
| `quarantine_dir` / `quarantine_min_confidence` | Evidence vault for file-based high-confidence detections. |
| `rate_limit_per_rule_per_min` / `spool_dir` / `spool_max_bytes` | Per-rule rate limit and disk-backed spool. |
| `selfguard.binary_path` / `selfguard.expected_sha256` / `selfguard.check_interval` | Agent self-integrity + systemd watchdog. |
| `baseline_commit_token_env` | Env var name holding the 2FA token for `baseline commit`. |
| `syslog_udp`, `syslog_tcp`, `splunk_hec`, `elastic_bulk`, `loki_push` | Nested sink blocks (see SIEM section). |
| `ld_preload_allowlist`, `path_allowlist_prefixes`, `network_allow_cidrs` | Reduce false positives. |

---

## Rule pack

The rule pack is versioned (`version` field) and defines per-rule `id`, MITRE `techniques`, `min_signals`, score weights, an optional boolean `expr` expression, and optional `correlate` peers with `correlate_window` / `correlate_boost`. Ship it next to the binary or under `/etc/ghostcatcher/` and point `rule_pack_path` at it.

Expression mini-language:

```
signal("WEB_SHELL_PATTERN") and confidence >= 70
comm in ["sh","bash","nc"] and not parent_comm in ["systemd","init"]
matches(entity_path, "^/tmp/.*\\.so$")
contains(evidence.cmdline, "base64 -d")
```

Sign a rule pack (ed25519):

```bash
# one-time: generate the key pair you will distribute
openssl genpkey -algorithm Ed25519 -out rulepack.key
openssl pkey -in rulepack.key -pubout -outform DER \
  | tail -c 32 | base64 > /etc/ghostcatcher/rulepack.pub

# on every change to /etc/ghostcatcher/rule_pack.yaml
openssl pkeyutl -sign -inkey rulepack.key \
  -in /etc/ghostcatcher/rule_pack.yaml \
  -out /etc/ghostcatcher/rule_pack.yaml.sig
```

Then set `rule_pack_pubkey_file` + `rule_pack_signature_file` in the agent config; loads fail closed on mismatch.

---

## Output format

Each emitted detection is written as one JSON object on **stdout** and forwarded (unchanged, aside from transport-level framing) to every enabled sink. Stable fields (schema **1.1**):

- Identity: `schema_version`, `agent_version`, `rule_pack_version`, `timestamp`, `rule_id`, `technique_id`, `tactic`, `severity`, `confidence`, `correlation_id`, `learning_only`, `dedup_key`.
- Entity: `entity` (type + path / comm / pid / network tuple).
- Context objects: `process` (pid, ppid, comm, exe, args, uid, euid, caps, ancestors), `file` (hash, size, mode, owner, mtime), `network` (local/remote IP + port, family, state, inode), `container` (runtime, id, pod_uid, image, namespace).
- Matching: `signals[]`, `evidence{}`, `ioc_matches[]`.

Pipe to your log stack or `jq`:

```bash
sudo ./ghostcatcher run -config configs/config.yaml -once | jq .
```

Operational messages from the CLI use **stderr** (e.g. `check-config`, baseline commit logs, sensor backend selection).

---

## Privileges

- **Root:** full coverage for other users’ `authorized_keys`, all PIDs’ `environ` / `maps` / `fd`, `/proc/net/*` ↔ inode mapping, kernel module enumeration, and system cron / systemd paths. Required for eBPF and `CAP_BPF` attach.
- **Non-root:** partial visibility (own processes, own home); many checks degrade or miss data.
- **Integrity module:** requires `/var/lib/dpkg` or the `rpm` CLI; silently skipped on distros where neither is present.

---

## Project layout

```
.
├── cmd/agent/             # CLI entrypoint (run | -once | baseline | check-config | eval)
├── configs/               # Example config + rule pack
├── .github/workflows/     # CI (build, vet, test, eval, golangci-lint, gosec, govulncheck, syft, cosign)
├── internal/
│   ├── baseline/          # JSON snapshot load/save (web files, keys, cron, ancestry, SUID, xattrs, kmods, .so inventory, …)
│   ├── config/            # YAML configuration with all sink + self-guard blocks
│   ├── detect/
│   │   ├── web/           # Regex + normalization + entropy + magic + PHP taint flow (php_ast.go)
│   │   ├── ldpreload/     # ld.so.preload + /proc/*/environ
│   │   ├── persistence/   # ssh, cron, systemd timers/services, pam, sudoers, shellrc, users, kmods, ld.so.conf
│   │   ├── memorymaps/    # /proc/*/maps: RWX / (deleted) / TracerPid / CapEff / .so allowlist
│   │   ├── integrity/     # dpkg (Debian) + rpm (RHEL) + SUID/SGID delta + security.capability xattr
│   │   ├── network/       # /proc/net/{tcp,tcp6,udp,udp6} × /proc/*/fd reverse-shell + listen delta
│   │   ├── ancestry/      # PROC_RARE_ANCESTRY
│   │   ├── copyfail/      # CVE-2026-31431 AF_ALG AEAD + SUID page-cache poisoning
│   │   └── yara/          # Stub by default; cgo build with -tags with_yara
│   ├── event/             # Event schema 1.1 (process / file / network / container / correlation_id)
│   ├── ioc/               # Hash / IP / CIDR / domain feed loader + enrichment
│   ├── procfs/            # /proc helpers (ancestry, cgroup, env, fds, net, maps)
│   ├── rules/             # Rule pack load, expression evaluator, sigma-lite loader, ed25519 verify
│   ├── runner/            # Scan orchestration, dedup, correlation, sensor glue, emit/spool
│   ├── sensor/            # Auto() → eBPF (with_ebpf) | auditd tail | /proc poll
│   ├── quarantine/        # Evidence vault (file + JSON sidecar)
│   ├── selfguard/         # Binary sha256 + systemd watchdog
│   ├── eval/              # Precision / recall / F1 harness
│   ├── watch/             # fsnotify (keys, ld.so.preload, cron, systemd, sudoers, pam, sshd, docroots, passwd/shadow)
│   └── export/
│       ├── syslog/        # UDP RFC5424 / RFC3164
│       ├── syslogtcp/     # RFC5425 TCP / TLS
│       ├── splunk/        # HEC
│       ├── elastic/       # _bulk
│       └── loki/          # push API
├── systemd/               # Example unit file
└── testdata/
    ├── web/               # Sample web files for tests
    └── eval/              # Labeled malicious + benign corpus for ghostcatcher eval
```

---

## Limitations

- **Not** a replacement for enterprise EDR, managed threat hunting, or kernel-level enforcement.
- **eBPF sensor** requires kernel ≥ 5.8 and `CAP_BPF`; older hosts auto-fall back to `auditd` then `/proc` polling, losing some fidelity.
- **YARA** requires a cgo build (`-tags with_yara`) with libyara headers; the default stub returns no matches.
- **Network-side correlation:** out-of-host flow analysis still depends on **IDS** or netflow collectors; the agent only observes sockets visible in `/proc/net/*`.
- **Heuristics** can false-positive (especially `maps` RWX and broad PHP patterns)—use **baselines**, **allowlists**, and **`min_confidence_for_alert`**.
- **Rule pack signing** protects at-rest and at-load; if an attacker already has root and can alter process memory, `selfguard` can still flip to `AGENT_TAMPERED` but cannot self-heal.

---

## Contributing

Issues and PRs are welcome: docs, tests, tuning guides, and optional backends (e.g. RPM verification, eBPF event ingestion).

**Before a PR:** `go test ./...`, `go vet ./...`, and run `check-config` with your sample YAML.

---

## License

Released under the [MIT License](LICENSE).

---

## Security

For vulnerability reports, see [`SECURITY.md`](SECURITY.md). Do not open public issues for undisclosed exploitable bugs until coordinated disclosure is complete.
