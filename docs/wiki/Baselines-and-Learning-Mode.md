# Baselines and Learning Mode

GhostCatcher's two-stage detection model — a stable **baseline** plus runtime **delta** — is what keeps it usable in production. This page explains what the baseline contains, the lifecycle of the snapshot file, the learning workflow you should run before turning on alerts, and the optional 2FA on `baseline commit`.

## What the baseline contains

A baseline is a JSON snapshot at `baseline_path` (typically `/var/lib/ghostcatcher/baseline.json`). It is produced by `ghostcatcher baseline commit` and consumed by every detector at startup and on every scan. Today it holds:

| Field | Source | Used by |
|-------|--------|---------|
| `web_files{}` | hash + size + mtime + owner of every file under `document_roots` matching the configured extensions | web shell scanner (`WEB_FILE_NEW`, `WEB_FILE_HASH_DRIFT`) |
| `authorized_keys{}` | per-user fingerprints from `~/.ssh/authorized_keys` | `SSH_KEY_NEW` |
| `cron_lines[]` | normalized lines from `/etc/crontab`, `/etc/cron.*/`, `/var/spool/cron/*`, `/var/spool/atjobs` | `CRON_FILE_NEW`, `CRON_RISK_LINE` |
| `ld_preload[]` | values from `/etc/ld.so.preload` and `/proc/*/environ` for watched comms | `LD_PRELOAD_NEW`, `LD_PRELOAD_FILE` |
| `persistence_files{}` | hash of every file under shellrc, pam, sudoers, sshd_config, systemd, modprobe paths | all `*_DRIFT` rules |
| `loaded_kernel_modules[]` | `/proc/modules` snapshot | `KMOD_LOADED_NEW` |
| `suid_inventory{}` | path + hash of every SUID/SGID binary under `suid_watch_dirs` | `SUID_NEW`, `SUID_HASH_DRIFT` |
| `file_capabilities{}` | `security.capability` xattr per file under `caps_watch_dirs` | `CAPS_DRIFT` |
| `process_ancestry{}` | observed `(parent_comm, child_comm)` pairs at commit time | `PROC_RARE_ANCESTRY` |
| `loaded_libraries{}` | per-`comm` set of `.so` paths from `/proc/*/maps` | `MAPS_SO_NEW` |
| `network_listeners{}` | `comm:port:proto` triples at commit time | `NET_LISTEN_NEW` |
| `committed_at` | UTC timestamp of the commit | logging / forensics |

The on-disk format is a single JSON object that is `0600` and owned by root. Avoid storing it on a network share — keep it on local disk so an attacker with read access to a file server cannot use it as recon.

## Commit lifecycle

```text
                 +-----------------+
                 |  fresh install  |
                 +--------+--------+
                          |
                          v
            ghostcatcher run  (learning_mode=true)
                          |
                          v
                +---------+----------+
                | observe → tune     |
                | (path allowlists,  |
                |  rule weights,     |
                |  IOC feeds)        |
                +---------+----------+
                          |
                          v
              ghostcatcher baseline commit
                          |
                          v
            ghostcatcher run  (learning_mode=false)
                          |
                          v
                +---------+----------+
                | live alerts        |
                +--------------------+
```

After a commit, every subsequent run is a **delta** against that snapshot. A new file in `document_roots` becomes `WEB_FILE_NEW`; a new SUID binary becomes `SUID_NEW`; a new `(nginx, sh)` ancestry becomes `PROC_RARE_ANCESTRY`. Rotating the baseline acknowledges all current state as known good, so do not commit during incident response.

## Learning mode

`learning_mode: true` (or `min_confidence_for_alert` set very high) keeps the agent producing JSON for every detection, but every event has `learning_only: true`, which most SIEM dashboards filter out by default. Use it to:

1. Capture realistic noise from your production workload.
2. Build path / IP / IOC allowlists from the noisy events.
3. Tune rule weights and `min_signals` until the noise floor is acceptable.
4. Flip `learning_mode: false` (or lower `min_confidence_for_alert`) and ship.

`first_run_allow_alerts: true` is an escape hatch for net-new installs where you want some alerting before the first commit (rare; usually only when responding to an active incident on a host that never had GhostCatcher).

## Path allowlists

Most false positives reduce to two questions:

- **Web roots:** does the framework drop generated PHP into a writable cache? Add the cache prefix to `path_allowlist_prefixes`.
- **`/proc/maps`:** does a JIT (Java, .NET, V8) legitimately allocate RWX in `/dev/shm`? Add the matching prefix to `maps_path_allowlist_prefixes`.

Both lists support exact prefix matches; there is no glob to keep matching cheap.

## Rotating the baseline

Rotate when the host changes intentionally — a new release, a new web app deploy, a kernel module update. The recommended sequence:

```bash
sudo systemctl stop ghostcatcher

# (optional) snapshot the previous baseline for forensic comparison
sudo cp /var/lib/ghostcatcher/baseline.json \
        /var/lib/ghostcatcher/baseline.$(date -u +%Y%m%dT%H%M%S).json

sudo ghostcatcher baseline commit -config /etc/ghostcatcher/config.yaml
sudo systemctl start ghostcatcher
```

Keep at least the last few snapshots so you can diff after the fact (`jq -S . baseline.<old>.json > a; jq -S . baseline.<new>.json > b; diff a b`).

## Two-factor commit (recommended in production)

`baseline commit` is the single most powerful command in the agent — anyone who can run it can hide an attacker's changes by absorbing them into the snapshot. Optional 2FA closes that gap.

Enable it:

```yaml
baseline_commit_token_env: GC_BASELINE_TOKEN
```

Now an attacker with root must also know the value of `$GC_BASELINE_TOKEN` to commit. Provide it via your secret manager:

```bash
GC_BASELINE_TOKEN="$(vault kv get -field=token kv/ghostcatcher/2fa)" \
  sudo -E ghostcatcher baseline commit \
       -config /etc/ghostcatcher/config.yaml \
       -token "$GC_BASELINE_TOKEN"
```

The implementation lives in [`cmd/agent/main.go`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/cmd/agent/main.go) → `baselineCommit`. If the env var is set but the `-token` flag is missing or wrong, the command exits non-zero and writes nothing.

## Watching the baseline file

If you also want to know **when** the baseline file changes (legitimate or not), point your file integrity monitor or a dedicated `auditd` rule at it:

```
-w /var/lib/ghostcatcher/baseline.json -p wa -k gc_baseline
```

GhostCatcher does not watch its own baseline by design — it is a state file, not a detection target.

## Cross-references

- **[Configuration](Configuration)** for the keys mentioned above.
- **[Operations Runbook](Operations-Runbook)** for the day-2 procedures (post-deploy, post-incident, key rotation).
- **[Quarantine and Self Guard](Quarantine-and-Self-Guard)** for the analogous protections on the running binary.
