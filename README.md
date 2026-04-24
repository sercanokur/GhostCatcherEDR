# GhostCatcher (endpoint agent)

A lightweight **Linux endpoint** detection agent written in **Go**. It runs as a CLI or **systemd** service, scans the host on an interval (and optionally watches `authorized_keys` via **fsnotify**), and emits **one JSON object per line** on stdout for SIEM pipelines.

GhostCatcher focuses on **host-visible** behaviors aligned with common intrusion patterns (web shells, `LD_PRELOAD` hijacking, SSH/cron persistence), using **baselines**, **multi-signal scoring**, and a **versioned rule pack**—not a full EDR suite.

> **Scope:** No kernel driver, no TLS inspection, no managed cloud backend. Complements network sensors, eBPF tracers, and auditd rather than replacing them.

---

## Table of contents

- [Features](#features)
- [What it detects (summary)](#what-it-detects-summary)
- [Requirements](#requirements)
- [Build](#build)
- [Quick start](#quick-start)
- [Install on a server (production)](#install-on-a-server-production)
- [Configuration checklist](#configuration-checklist)
- [SIEM integration (syslog / JSON)](#siem-integration-syslog--json)
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

| Area | Mechanism |
|------|-----------|
| **Web shell / PHP–style patterns** | Regex/YARA-style pattern set on configured document roots; optional correlation with **web worker → shell child** and **recon-style argv** under workers (`whoami`, `ifconfig`, `uname`, …). |
| **Fileless / memory hint** | Optional **`/proc/[pid]/maps` RWX** scan for selected processes (e.g. `nginx`, `apache2`). |
| **`LD_PRELOAD` / preload file** | `/etc/ld.so.preload` and `LD_PRELOAD` in **`/proc/[pid]/environ`** for configured process names; allowlists in config. |
| **SSH persistence** | `~/.ssh/authorized_keys` fingerprints vs **baseline**; invalid line anomaly. |
| **Cron persistence** | `/etc/crontab`, `/etc/cron.d/*`, user crontabs; **high-risk tokens** (e.g. `curl`, `bash -c`, `base64 -d`) vs baseline. |
| **Binary integrity (Debian/Ubuntu)** | Optional **`dpkg` md5sums** check for critical paths (`ls`, `ps`, `ss`, …). |
| **Real-time SSH files** | Optional **fsnotify** rescan when `authorized_keys` changes. |
| **Syslog / SIEM (UDP)** | Optional **RFC5424** or **RFC3164** syslog with the same JSON payload in the **MSG** field to a collector (`host`:`port`, e.g. 514). |

Baseline is stored as JSON (`baseline commit`). Alerts respect **`min_confidence_for_alert`** and **`learning_only`** until you freeze a baseline.

---

## What it detects (summary)

Rules are defined in the YAML **rule pack**; each emitted event includes `technique_id` (MITRE-style IDs) and `rule_id`. Examples:

- **T1505.003** / **T1059.004** — web patterns, worker children, recon argv.
- **T1574.006** / **T1014** — `LD_PRELOAD`, `ld.so.preload`.
- **T1098.004** — new authorized key fingerprints.
- **T1053.003** — high-risk cron deltas.
- **T1055** (hint) — RWX mappings in server processes.
- **T1036** — md5 mismatch vs `dpkg` for watched binaries.

Exact scoring and `min_signals` per rule are in [`configs/rule_pack.example.yaml`](configs/rule_pack.example.yaml).

---

## Requirements

- **Go** 1.22 or newer (see [`go.mod`](go.mod)).
- **Runtime:** Linux (Ubuntu/Debian-class distros for `dpkg` integrity checks). `/proc`-based features are Linux-specific.
- **Recommended:** run as **root** for full `/proc` visibility across users and PIDs (see [Privileges](#privileges)).

---

## Build

```bash
git clone https://github.com/<your-org>/GhostCatcherEntpointDetection.git
cd GhostCatcherEntpointDetection
go build -o ghostcatcher ./cmd/agent
```

Run tests:

```bash
go test ./...
```

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

5. Run continuously (interval from `scan_interval`):

   ```bash
   sudo ./ghostcatcher run -config configs/config.yaml
   ```

Example **systemd** unit: [`systemd/ghostcatcher.service`](systemd/ghostcatcher.service).

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
| `syslog_udp` | Set `enabled: true`, `host`, `port` when the SIEM or a syslog relay listens for UDP. |
| `require_root: true` | Enforces root so the agent fails fast if started without full `/proc` coverage. |

### Optional / environment-specific

| Setting | When |
|---------|------|
| `maps_scan_enabled` | Linux web servers; expect possible false positives—use `maps_path_allowlist_prefixes` after testing. |
| `integrity_verify_enabled` | Debian/Ubuntu only; verifies `integrity_paths` against `dpkg` md5sums. |
| `watch_authorized_keys` | Faster reaction to `authorized_keys` edits; needs readable `.ssh` dirs. |
| `learning_mode` | `true` during pilot; set `false` once baselines and thresholds are trusted. |
| `first_run_allow_alerts` | Usually `false`; only if you explicitly want higher-severity alerts before the first `baseline commit`. |

After any change: `sudo ghostcatcher check-config -config /etc/ghostcatcher/config.yaml` then `sudo systemctl restart ghostcatcher` (if using systemd).

---

## SIEM integration (syslog / JSON)

The agent can send **the same JSON event** both to **stdout** and to a **syslog receiver over UDP** (`syslog_udp` in config).

### What the SIEM receives

- **Transport:** UDP to `syslog_udp.host`:`syslog_udp.port` (common ports: **514**, or a dedicated port like **5514** to avoid mixing with OS syslog).
- **Framing:** **RFC5424** by default (`format: rfc5424`). The structured detection is in the **MSG** field as a **single-line JSON** object (fields such as `rule_id`, `technique_id`, `severity`, `confidence`, `entity`, `evidence`, …).
- **Severity mapping:** syslog PRI is derived from facility (e.g. `local0`) and from the event’s `severity` (`critical` → lower numeric syslog severity, etc.).

### Collector-side checklist

1. Open a **UDP** input on the SIEM or on a relay (rsyslog, syslog-ng, Splunk Universal Forwarder, Elastic Agent, etc.) that matches `host`/`port`.
2. Configure the parser to treat the **MSG** (after the RFC5424 header) as **JSON** (or run a pipeline rule to `json` parse that substring).
3. If messages are truncated, raise **`max_msg_bytes`** in Ghostcatcher (watch UDP size limits on your network and SIEM; very large events may still be dropped).
4. For **TLS** or **TCP** syslog, put a **relay** in front (e.g. syslog-ng receives UDP from hosts and forwards signed/TCP to the SIEM)—this agent only implements **UDP** syslog.

### Example `syslog_udp` block

```yaml
syslog_udp:
  enabled: true
  host: siem-collector.internal   # or IP of HF / log server
  port: 5514
  format: rfc5424
  facility: local0
  app_name: ghostcatcher
  hostname: web-prod-01          # optional; visible in syslog header
  max_msg_bytes: 8192
```

### If you do not use syslog

Point **journald** or a log shipper at the service stdout (JSON lines) and parse JSON there—the payload schema is the same as in the syslog MSG.

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
| `document_roots` | Web roots to walk for `.php` / `.jsp` / `.phtml`. |
| `baseline_path` | JSON snapshot path. |
| `rule_pack_path` | YAML rules + scoring metadata. |
| `min_confidence_for_alert` | Minimum `confidence` to treat as production alert (still emitted as JSON; `learning_only` may apply). |
| `learning_mode` | Force learning-style severity for tunable workflows. |
| `require_root` | Exit if not UID 0 when true. |
| `maps_scan_enabled` | `/proc/maps` RWX heuristic for `maps_watch_processes`. |
| `integrity_verify_enabled` | `dpkg` md5 verification for `integrity_paths`. |
| `web_recon_child_scan_enabled` | Recon argv under web workers. |
| `watch_authorized_keys` | fsnotify-triggered rescans. |
| `syslog_udp` | Nested block: `enabled`, `host`, `port`, `format` (`rfc5424` / `rfc3164`), `facility` (e.g. `local0`), `app_name`, optional `hostname`, `max_msg_bytes`. |
| `ld_preload_allowlist`, `path_allowlist_prefixes` | Reduce false positives. |

---

## Rule pack

The rule pack is versioned (`version` field) and defines per-rule `id`, MITRE `techniques`, `min_signals`, and score weights. Ship it next to the binary or under `/etc/ghostcatcher/` and point `rule_pack_path` at it.

---

## Output format

Each emitted detection is written as one JSON object on **stdout**. If **`syslog_udp.enabled`** is true, the **same** JSON (possibly truncated to `max_msg_bytes`) is also sent in the syslog **MSG** over **UDP** to the configured SIEM listener.

Stable fields include:

`schema_version`, `agent_version`, `timestamp`, `rule_id`, `rule_pack_version`, `technique_id`, `tactic`, `confidence`, `severity`, `entity`, `signals`, `dedup_key`, `evidence`, `learning_only`.

Pipe to your log stack or `jq`:

```bash
sudo ./ghostcatcher run -config configs/config.yaml -once | jq .
```

Operational messages from the CLI use **stderr** (e.g. `check-config`, baseline commit logs).

---

## Privileges

- **Root:** full coverage for other users’ `authorized_keys`, all PIDs’ `environ`/`maps`, and system cron paths.
- **Non-root:** partial visibility (own processes, own home); many checks degrade or miss data.
- **Integrity module:** requires `/var/lib/dpkg` (Debian/Ubuntu); silently skipped elsewhere.

---

## Project layout

```
.
├── cmd/agent/           # CLI entrypoint
├── configs/             # Example config + rule pack
├── internal/
│   ├── baseline/        # JSON snapshot load/save
│   ├── config/          # YAML configuration
│   ├── detect/
│   │   ├── web/         # Web shell patterns, recon children, web baseline
│   │   ├── ldpreload/   # ld.so.preload + process env
│   │   ├── persistence/ # SSH keys + cron
│   │   ├── memorymaps/  # RWX /proc/maps heuristic
│   │   └── integrity/   # dpkg md5sums
│   ├── event/           # JSON event schema
│   ├── procfs/          # /proc helpers
│   ├── rules/           # Rule pack load + scoring
│   ├── runner/          # Scan orchestration, dedup
│   ├── watch/           # Optional fsnotify for SSH paths
│   └── export/
│       └── syslog/      # UDP syslog (RFC5424 / RFC3164)
├── systemd/             # Example unit file
└── testdata/            # Sample web files for tests
```

---

## Limitations

- **Not** a replacement for enterprise EDR, managed threat hunting, or kernel-level enforcement.
- **No built-in eBPF** or **auditd** syscall tracing; recon argv and `/proc` trees approximate some of those signals.
- **No NDR:** correlating cron-driven processes to outbound beacons requires external network monitoring.
- **Heuristics** can false-positive (especially `maps` RWX and broad PHP patterns)—use **baselines**, **allowlists**, and **`min_confidence_for_alert`**.
- **Integrity** is `dpkg`-centric; other distros need a different backend if you extend the agent.

---

## Contributing

Issues and PRs are welcome: docs, tests, tuning guides, and optional backends (e.g. RPM verification, eBPF event ingestion).

**Before a PR:** `go test ./...`, `go vet ./...`, and run `check-config` with your sample YAML.

---

## License

Add a `LICENSE` file to the repository before publishing (e.g. **MIT**, **Apache-2.0**, or **GPL-3.0**). This README does not impose a license by itself.

---

## Security

For vulnerability reports, add a [`SECURITY.md`](SECURITY.md) with contact details (e.g. GitHub Security Advisories or a dedicated email). Do not open public issues for undisclosed exploitable bugs until coordinated disclosure is complete.
