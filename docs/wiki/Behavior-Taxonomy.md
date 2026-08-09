# Behavior Taxonomy

GhostCatcher detections are organized as an Ubuntu **Macro → Micro → Nano** behavior tree. The human-readable doctrine is [`bhv.md`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/bhv.md); the machine-readable catalog is [`configs/mapping.yaml`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/configs/mapping.yaml).

## Layers

| Layer | Example | Role |
|-------|---------|------|
| **Macro** | `M1` … `M6` | Attack story (web RCE, persistence, privesc, concealment, credentials, container escape) |
| **Micro** | `M1.2`, `M2.4` | Technique family inside a macro |
| **Nano** | `WEB_WORKER_SHELL_CHILD` | Atomic detection — emitted as `rule_id` |

Every emitted event (schema **1.3**) carries taxonomy fields filled from `mapping.yaml` during Orient:

| Event field | Source |
|-------------|--------|
| `rule_id` | Nano ID |
| `macro` / `micro` | Catalog |
| `src` | Telemetry honesty label (`AUDIT`, `FIM`, `PROCSCAN`, `INVENTORY`, `EBPF-*`) |
| `type` | `EVENT` \| `DELTA` \| `STATE` |
| `anchor` | cgroup v2 path or systemd unit — **not** process name |
| `conf_band` | Standalone nano confidence: `HIGH` \| `MEDIUM` \| `LOW` |

Numeric `confidence` (0–100) still comes from the rule pack scorer; `conf_band` is the bhv band.

## Macros at a glance

| Macro | Theme | Primary packages |
|-------|-------|------------------|
| **M1** | Persistent command execution via internet-facing apps | `detect/web`, `detect/network`, `detect/ancestry` |
| **M2** | Persistence via admin mechanisms (SSH, cron, systemd, Ubuntu hooks) | `detect/persistence`, `detect/fimextra` |
| **M3** | Privilege escalation and defense weakening | `detect/ldpreload`, `detect/integrity`, `detect/defense`, `detect/privesc`, `detect/copyfail` |
| **M4** | Concealment / anti-forensics | `detect/memorymaps`, `detect/sensorlive`, `detect/defense` |
| **M5** | Credential access | `detect/credential` |
| **M6** | Container / virt boundary violation | `detect/containeresc` |

Non-bhv rules stay in the catalog, mapped to the nearest macro:

| Rule | Macro |
|------|-------|
| `YARA_DISK_MATCH` | M1.1 |
| `YARA_PROCESS_MATCH` | M4.1 |
| `CVE_2026_31431_*` | M3.2 |
| `AGENT_TAMPERED` | M3.3 |
| `PROC_CAP_ESCALATION` | M3.2 |
| `KERNEL_MODLOAD_PATH_CHANGED` | M3.3 |

## Anchor rule

Process `comm` is never the primary correlation key. Prefer:

1. systemd unit from cgroup (`nginx.service`, `php8.3-fpm.service`) via [`internal/anchor`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/internal/anchor)
2. cgroup v2 path
3. `ld_preload_target_processes` / process name as fallback only

Configure primary web units with `watched_units` and benign maintainers with `fp_allowlist_units` (see [Configuration](Configuration)).

## Correlation chains

Individually medium nanos become high confidence in an **ordered**, **time-windowed**, **same-anchor** chain (`internal/runner/correlation.go`):

| ID | Window | Story |
|----|--------|-------|
| CHAIN-1 | 30m | Web RCE → shell/interp → downloader/listen → persistence |
| CHAIN-2 | 10m | Interp child → IMDS → cloud cred / egress |
| CHAIN-3 | 15m | Sudden root / GTFOBins / unpackaged SUID → priv group / sudoers / PAM |
| CHAIN-4 | 20m | Sysctl / AppArmor / auditd tamper → tracer / mem read / kmod |
| CHAIN-5 | 10m | Docker/LXD socket abuse → setns / host mount |
| CHAIN-6 | 60m | Any HIGH → journal/log/history wipe (`evidence_loss: true`) |

On a hit the event gains `chain_id`, severity `critical`, signal `chain:CHAIN-N`, and optionally `evidence_loss`.

## Rule packs vs mapping

| File | Purpose |
|------|---------|
| `configs/mapping.yaml` | Full nano catalog + chains (taxonomy source of truth) |
| `configs/lab_rule_pack.yaml` | Lab/demo scoring for the full catalog (~100+ rules) |
| `configs/rule_pack.example.yaml` | Production-oriented subset |

`internal/taxonomy` loads `mapping_path` (or auto-resolves `configs/mapping.yaml`) at runner start and applies metadata to every event.

## Where to go next

- **[Detections](Detections)** — nano inventory by macro
- **[Architecture](Architecture)** — packages and pipeline
- **[Rule Pack](Rule-Pack)** — scoring YAML + `expr` / `correlate`
- **[Doctrine](Doctrine)** — OODA / Kill Chain / ATT&CK overlay
