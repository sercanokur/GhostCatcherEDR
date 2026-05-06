# Getting Started

This page walks through installing GhostCatcher on a single host, validating the configuration, taking a first baseline, and running scans either ad-hoc or as a `systemd` service.

## 1. Prerequisites

- A Linux host (Debian/Ubuntu or RHEL/CentOS/Fedora preferred for integrity coverage).
- Go ≥ 1.22 if you build from source.
- Root privileges for full visibility (cron paths, other users' `authorized_keys`, all PIDs in `/proc`).
- Optional: kernel ≥ 5.8 if you want the eBPF sensor.
- Optional: libyara ≥ 4.3 if you want the YARA scanner.

## 2. Build the binary

```bash
git clone https://github.com/sercanokur/GhostCatcherEDR.git ghostcatcher
cd ghostcatcher
go build -o ghostcatcher ./cmd/agent
```

Optional build tags:

```bash
# eBPF exec/openat/connect/ptrace/init_module/memfd sensor
go build -tags with_ebpf -o ghostcatcher ./cmd/agent

# YARA disk + memory scanning (requires libyara headers)
CGO_ENABLED=1 go build -tags with_yara -o ghostcatcher ./cmd/agent

# Both
CGO_ENABLED=1 go build -tags "with_yara with_ebpf" -o ghostcatcher ./cmd/agent
```

See **[Build Tags](Build-Tags)** for what each tag enables and when you actually want it.

## 3. Install the binary and configs

```bash
sudo install -m 0755 ghostcatcher /usr/local/bin/ghostcatcher
sudo mkdir -p /etc/ghostcatcher /var/lib/ghostcatcher
sudo cp configs/config.example.yaml      /etc/ghostcatcher/config.yaml
sudo cp configs/rule_pack.example.yaml   /etc/ghostcatcher/rule_pack.yaml
sudo chmod 0640 /etc/ghostcatcher/config.yaml /etc/ghostcatcher/rule_pack.yaml
```

Edit `/etc/ghostcatcher/config.yaml` and at minimum set:

| Key | Why |
|-----|-----|
| `baseline_path` | e.g. `/var/lib/ghostcatcher/baseline.json` |
| `rule_pack_path` | `/etc/ghostcatcher/rule_pack.yaml` |
| `document_roots` | actual web roots on this host (nginx `root`, Apache `DocumentRoot`) |
| `require_root: true` | so the agent fails fast if launched without root |
| One of the sink blocks | `syslog_udp`, `syslog_tcp`, `splunk_hec`, `elastic_bulk`, `loki_push` |

Full key reference is in **[Configuration](Configuration)**.

## 4. Validate

```bash
sudo ghostcatcher check-config -config /etc/ghostcatcher/config.yaml
```

This loads the YAML, validates required fields, and parses the rule pack (including any compiled expressions). It exits non-zero on any failure, which makes it safe to call from CI.

## 5. Take the first baseline

A baseline is the “known good” snapshot: web file hashes, `authorized_keys` fingerprints, cron lines, `LD_PRELOAD` values, persistence paths, loaded kernel modules, SUID inventory, file capabilities, process ancestry, and per-process loaded shared libraries.

Run when the host is in a known-good state:

```bash
sudo ghostcatcher baseline commit -config /etc/ghostcatcher/config.yaml
```

If you have configured `baseline_commit_token_env`, also pass `-token`:

```bash
GC_BASELINE_TOKEN="$(pass ghostcatcher/2fa)" \
  sudo -E ghostcatcher baseline commit \
       -config /etc/ghostcatcher/config.yaml \
       -token "$GC_BASELINE_TOKEN"
```

See **[Baselines and Learning Mode](Baselines-and-Learning-Mode)** for what the snapshot covers and how to rotate it safely.

## 6. Run a single scan

```bash
sudo ghostcatcher run -config /etc/ghostcatcher/config.yaml -once | jq .
```

Each detection is one JSON object on stdout. Operational logs go to stderr.

## 7. Run continuously

```bash
sudo ghostcatcher run -config /etc/ghostcatcher/config.yaml
```

This:

- ticks at `scan_interval` for periodic full passes,
- starts the realtime sensor (eBPF / auditd / proc-poll, in that preference order),
- starts `fsnotify` watchers for sensitive paths (`authorized_keys`, `ld.so.preload`, cron, systemd, sudoers, pam, sshd, document roots, `passwd`/`shadow`),
- emits to every enabled sink, and
- spools to disk if a sink is unreachable.

## 8. Install the systemd unit

```bash
sudo cp systemd/ghostcatcher.service /etc/systemd/system/ghostcatcher.service
sudo systemctl daemon-reload
sudo systemctl enable --now ghostcatcher.service
sudo systemctl status ghostcatcher.service
journalctl -u ghostcatcher -f
```

If you want the self-guard watchdog to keep the agent alive, set in the unit:

```ini
[Service]
Type=notify
WatchdogSec=30
```

…and configure `selfguard.binary_path` + `selfguard.expected_sha256` in the YAML. See **[Quarantine and Self Guard](Quarantine-and-Self-Guard)**.

## 9. Verify detection quality

Run the bundled evaluation harness against the labeled corpus to make sure your rule pack still meets your precision/recall floor:

```bash
ghostcatcher eval -corpus testdata/eval -min-f1 0.85
```

See **[Evaluation Harness](Evaluation-Harness)**.

## Next

- **[Architecture](Architecture)** — what runs where, in pictures.
- **[Detections](Detections)** — what the shipped rules actually catch.
- **[Operations Runbook](Operations-Runbook)** — restarts, baseline rotation, IOC refresh, key rotation.
