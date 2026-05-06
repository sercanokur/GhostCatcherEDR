# Configuration

The agent reads a single YAML file (default `configs/config.example.yaml`, production target `/etc/ghostcatcher/config.yaml`). Every key is optional unless marked **required**; sensible defaults live in `internal/config/config.go`. Run `ghostcatcher check-config -config <path>` before restarting the service to validate.

## Top-level keys

### Core

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `scan_interval` | duration | `5m` | Period of the full scan loop. |
| `baseline_path` | path | **required** | Where the JSON snapshot lives. |
| `rule_pack_path` | path | **required** | YAML rule pack. |
| `min_confidence_for_alert` | int | `70` | Events under this become `learning_only`. |
| `learning_mode` | bool | `false` | Force every event to `learning_only`, regardless of confidence. |
| `first_run_allow_alerts` | bool | `false` | Allow alerts before the first `baseline commit`. |
| `require_root` | bool | `true` | Exit non-zero if not running as UID 0. |
| `agent_log_level` | string | `info` | `debug` / `info` / `warn` / `error`. |

### Web detection

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `document_roots` | []path | `[]` | Web roots to walk. |
| `web_extensions` | []string | shipped list | Override the default extension set if needed. |
| `web_recon_child_scan_enabled` | bool | `true` | Recon children under web workers. |
| `path_allowlist_prefixes` | []path | `[]` | Skip paths matching these prefixes in web scanning. |

### `LD_PRELOAD`

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `ld_preload_watch_processes` | []string | shipped list | Process `comm`s whose `environ` is sampled. |
| `ld_preload_allowlist` | []string | `[]` | Path fragments to ignore. |

### `/proc/maps`

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `maps_scan_enabled` | bool | `true` | Enable RWX/`(deleted)`/TracerPid checks. |
| `maps_watch_processes` | []string | shipped list | `comm`s whose `/proc/maps` is read. |
| `maps_path_allowlist_prefixes` | []path | shipped list | Quiet known-good paths. |

### Integrity

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `integrity_verify_enabled` | bool | `true` | Auto-dispatches dpkg vs rpm via `/etc/os-release`. |
| `integrity_paths` | []path | shipped list | Files to verify (`/usr/bin/ls`, `/bin/ps`, …). |
| `suid_watch_dirs` | []path | shipped list | Where to walk for SUID/SGID drift. |
| `caps_watch_dirs` | []path | shipped list | Where to read `security.capability` xattrs. |

### Persistence + watchers

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `watch_authorized_keys` | bool | `true` | Master switch for fsnotify. |
| `cron_watch_paths` | []path | shipped list | Add custom cron locations. |
| `systemd_watch_paths` | []path | shipped list | Custom systemd unit dirs. |
| `pam_watch_paths` | []path | shipped list | |
| `sudoers_watch_paths` | []path | shipped list | |
| `sshd_config_watch_paths` | []path | shipped list | |
| `kmod_watch_paths` | []path | shipped list | |

### Process ancestry

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `ancestry_scan_enabled` | bool | `true` | Emits `PROC_RARE_ANCESTRY`. |
| `ancestry_juicy_parents` | []string | shipped list | Override the parent set. |
| `ancestry_child_set` | []string | shipped list | Override the child set. |

### Network

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `network_scan_enabled` | bool | `true` | |
| `network_allow_cidrs` | []cidr | `[127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, ::1/128, fc00::/7]` | Treat as internal. |
| `network_listen_baseline_required` | bool | `true` | If false, every listen is logged as informational. |

### YARA (only honored with `with_yara` build)

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `yara_rules_dir` | path | `""` | Directory of `*.yar` / `*.yara`. |
| `yara_memory_enabled` | bool | `false` | Scan live process memory in addition to disk. |
| `yara_memory_processes` | []string | shipped list | `comm`s to memory-scan. |

### IOC feeds

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `ioc_feed_dir` | path | `""` | Directory layout: `hash/`, `ip/`, `cidr/`, `domain/`. One indicator per line, `#` comments allowed. |
| `ioc_refresh_interval` | duration | `15m` | How often to re-read the directory. |
| `ioc_hash_boost` | int | `10` | Confidence delta on hash hit. |
| `ioc_network_boost` | int | `25` | Confidence delta on IP/CIDR/domain hit. |

### Sensor

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `sensor.disabled` | bool | `false` | Periodic scan only. |
| `sensor.backend` | enum | `auto` | `auto` / `ebpf` / `audit` / `proc`. |
| `sensor.debounce_ms` | int | `500` | Coalesce sensor bursts before triggering rescans. |

### Rate limit + spool

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `rate_limit_per_rule_per_min` | int | `60` | Drops in excess emit a single `RATE_LIMITED` event per window. |
| `spool_dir` | path | `/var/spool/ghostcatcher` | Where unsent events queue. |
| `spool_max_bytes` | int | `104857600` | Rotates the active file at this size. |

### Quarantine

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `quarantine_dir` | path | `""` (disabled) | Vault root. |
| `quarantine_min_confidence` | int | `85` | Only file-based events above this are stored. |
| `quarantine_max_bytes_per_artifact` | int | `33554432` | Skip oversized files. |

### Self-guard

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `selfguard.binary_path` | path | `""` | Absolute path to the running agent binary. |
| `selfguard.expected_sha256` | string | `""` | Hex digest. Mismatch emits `AGENT_TAMPERED`. |
| `selfguard.check_interval` | duration | `5m` | |
| `selfguard.systemd_watchdog` | bool | `true` | Emit `WATCHDOG=1` if `NOTIFY_SOCKET` is set. |

### Baseline 2FA

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `baseline_commit_token_env` | string | `""` | Env var holding the secret. `baseline commit -token <value>` must match. |

### Rule pack signing

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `rule_pack_pubkey_file` | path | `""` | Base64 ed25519 public key. |
| `rule_pack_signature_file` | path | `""` | Detached signature over `rule_pack_path`. |
| `sigma_lite_dir` | path | `""` | Sigma YAML drop-ins merged after the signed pack. |

### Sinks

See **[Sinks and SIEM](Sinks-and-SIEM)** for full transport details. The blocks are:

- `syslog_udp:` — UDP RFC5424 / RFC3164.
- `syslog_tcp:` — TCP, optional TLS, RFC5425 octet-counted.
- `splunk_hec:` — Splunk HTTP Event Collector.
- `elastic_bulk:` — Elasticsearch `_bulk`.
- `loki_push:` — Grafana Loki push API.

Each block has `enabled: true|false` and transport-specific fields documented in **[Sinks and SIEM](Sinks-and-SIEM)**.

## Validation

`ghostcatcher check-config` runs:

1. YAML parse.
2. Required-field check (`baseline_path`, `rule_pack_path`, at least one sink **or** stdout-only).
3. Path existence for files referenced (rule pack, signature, pubkey, baseline directory writable).
4. Rule pack load (compiles every `expr`).
5. Sigma-lite directory load (warns on unsupported subset).

Non-zero exit on any failure — wire this into your config-management pipeline so a bad change cannot reach a host without being caught first.

## Examples

The shipped `configs/config.example.yaml` has every key with a comment. For a minimal lab config:

```yaml
scan_interval: 1m
baseline_path: /var/lib/ghostcatcher/baseline.json
rule_pack_path: /etc/ghostcatcher/rule_pack.yaml
require_root: true
document_roots:
  - /var/www/html
syslog_udp:
  enabled: true
  host: 127.0.0.1
  port: 5514
  format: rfc5424
  facility: local0
  app_name: ghostcatcher
```

For a hardened production config see **[Operations Runbook](Operations-Runbook)**.
