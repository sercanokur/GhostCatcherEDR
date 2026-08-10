# Configuration

The agent reads a single YAML file (default `configs/config.example.yaml`, production `/etc/ghostcatcher/config.yaml`). Defaults live in `internal/config/config.go`. Validate with `ghostcatcher check-config -config <path>`.

## Core

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `scan_interval` | duration | `5m` | Full scan loop period. |
| `baseline_path` | path | **required** | JSON snapshot path. |
| `rule_pack_path` | path | **required** | Scoring rule pack YAML. |
| `mapping_path` | path | auto | bhv catalog (`configs/mapping.yaml`). Empty → resolve relative candidates. |
| `state_dir` | path | `/var/lib/ghostcatcher` | Agent state. |
| `min_confidence_for_alert` | int | `70` | Below → `learning_only`. |
| `learning_mode` | bool | `false` | Force every event `learning_only`. |
| `first_run_allow_alerts` | bool | `false` | Allow alerts before first baseline commit. |
| `require_root` | bool | `false` in example | Exit if not UID 0 when true. |

## Behavior taxonomy / anchors

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `watched_units` | []string | php-fpm / nginx / apache2 / … | Primary **web worker anchors** (unit name or prefix). |
| `fp_allowlist_units` | []string | apt/snap/cloud-init/logrotate/… | Benign units that should not escalate FIM noise (bhv §8). |
| `ld_preload_target_processes` | []string | nginx, apache2, … | Fallback process `comm` list when cgroup unit is unavailable. |

## Web detection

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `document_roots` | []path | `[]` | Docroots for shells / upload / tamper. |
| `web_recent_change_days` | int | `14` | Recent-mtime window. |
| `web_recon_child_scan_enabled` | bool | `true` | M1.2 worker children (recon/shell/interp/downloader/pty). |
| `path_allowlist_prefixes` | []path | `[]` | Skip prefixes in web walks. |

## LD_PRELOAD / maps / integrity

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `ld_preload_allowlist` | []string | `[]` | Benign preload paths. |
| `maps_scan_enabled` | bool | `false` | RWX / deleted / tracer / masquerade scans. |
| `maps_watch_processes` | []string | nginx, apache2, … | `comm`s to inspect. |
| `maps_path_allowlist_prefixes` | []path | `[]` | Quiet known-good map paths. |
| `integrity_verify_enabled` | bool | `false` | dpkg/rpm hash verify + SUID/caps. |
| `integrity_scan_interval` | duration | `6h` | Separate inventory ticker; `0` = every full scan. |
| `integrity_paths` | []path | shipped | Critical binaries to verify. |

## Watchers

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `watch_authorized_keys` | bool | `false` | Dedicated authkeys watcher. |
| `watch_debounce` | duration | `800ms` | fsnotify coalesce. |
| `watch_sensitive_paths` | bool | `true` | Broad FIM path set (SSH, cron, systemd, apt, motd, udev, …). |

## Network / ancestry / YARA / IOC

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `network_scan_enabled` | bool | `true` | `/proc/net` × fd correlation. |
| `network_scan_interval` | duration | `15m` | Throttle vs `scan_interval`; `0` = every full scan. |
| `network_ip_cidr_allowlist` | []cidr | RFC1918 + localhost | Treat as internal. |
| `sensor.backend` | string | `auto` | `auto` \| `ebpf` \| `auditd` \| `proc-poll`. |
| `sensor.debounce_ms` | int | `0` | Coalesce duplicate live events (raise on `ringbuffer.overrun`). |
| `ancestry_scan_enabled` | bool | `true` | `PROC_RARE_ANCESTRY`. |
| `yara_rules_dir` | path | `""` | Only with `-tags with_yara`. |
| `yara_memory_enabled` | bool | `false` | Process memory scan. |
| `ioc_hash_files` / `ioc_ip_files` / `ioc_domain_files` | []path | `[]` | One indicator per line. |

## Sudden root / copy-fail / respond

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `sudden_root.enabled` | bool | `true` | `PROC_SUDDEN_ROOT`. |
| `sudden_root.snapshot_interval` | duration | `10s` | Credential poll (`1s` ok in lab). |
| `sudden_root.allowed_exe_basenames` | []string | `[]` | Extra allowlist. |
| `copy_fail.enabled` | bool | `true` | CVE-2026-31431. |
| `copy_fail.page_cache_check_enabled` | bool | `false` | Periodic page-cache drift (opt-in; evicts cache). |
| `respond.enabled` | bool | `true` | OODA Act engine. |
| `respond.mode` | string | `audit` | `audit` \| `enforce`. |
| `respond.min_confidence` / `min_severity` | | | Gates for Act. |
| `respond.allow_quarantine` / `allow_kill_process` / `allow_isolate_host` | bool | | Per-action allow. |
| `respond.protected_comms` / `protected_pids` | | | Safety rails. |
| `respond.kill_switch` | bool | `false` | Disable all Act. |

## Rate limit / spool / quarantine / self-guard

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `rate_limit_per_rule_per_min` | int | `120` | Per `rule_id`. |
| `spool_dir` | path | `/var/lib/ghostcatcher/spool` | Unsent NDJSON. |
| `spool_max_bytes` | int64 | 64 MiB | Rotate cap. |
| `quarantine_dir` | path | `""` | Empty disables vault. |
| `quarantine_min_confidence` | int | | Gate for copy. |
| `self_guard.enabled` | bool | | Binary hash + watchdog. |
| `self_guard.binary_path` / `expected_binary_sha256` | | | Mismatch → `AGENT_TAMPERED`. |
| `baseline_commit_token_env` | string | `""` | Optional 2FA for `baseline commit`. |
| `rule_pack_pubkey_file` / `rule_pack_signature_file` | path | | ed25519 fail-closed verify. |
| `sigma_lite_dir` | path | `""` | Extra Sigma-lite drop-ins. |

## Sinks

See **[Sinks and SIEM](Sinks-and-SIEM)**. Blocks: `syslog_udp`, `syslog_tcp`, `splunk_hec`, `elastic_bulk`, `loki_push`.

## Host-cost profiles

Templates live under [`configs/profiles/`](../../configs/profiles/):

| File | Stance |
|------|--------|
| `light.yaml` | Low host impact (15m scan, ancestry off) |
| `balanced.yaml` | Matches `config.Default()` |
| `heavy-host.yaml` | Large trees / dense hosts (15m scan, throttled network) |
| `lab.yaml` | Aggressive demo cadence — not for production |

```bash
sudo cp configs/profiles/balanced.yaml /etc/ghostcatcher/config.yaml
# edit document_roots / sinks / pack paths
ghostcatcher check-config -config /etc/ghostcatcher/config.yaml
```

See `configs/profiles/README.txt` for install notes.

## Lab vs production packs

```yaml
# Lab / full catalog scoring
rule_pack_path: /etc/ghostcatcher/lab_rule_pack.yaml
mapping_path: /etc/ghostcatcher/mapping.yaml

# Production subset
rule_pack_path: /etc/ghostcatcher/rule_pack.yaml
mapping_path: /etc/ghostcatcher/mapping.yaml
```

Always ship `mapping.yaml` so events get macro/micro/`conf_band` even when the pack is a subset.

## Minimal example

```yaml
scan_interval: 1m
baseline_path: /var/lib/ghostcatcher/baseline.json
rule_pack_path: /etc/ghostcatcher/rule_pack.yaml
mapping_path: /etc/ghostcatcher/mapping.yaml
require_root: true
document_roots:
  - /var/www/html
watched_units:
  - nginx.service
  - php-fpm
syslog_udp:
  enabled: true
  host: 127.0.0.1
  port: 5514
  format: rfc5424
  facility: local0
  app_name: ghostcatcher
```

Full annotated file: [`configs/config.example.yaml`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/configs/config.example.yaml).
