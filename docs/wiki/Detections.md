# Detections

GhostCatcher detections follow the Ubuntu **Macro → Micro → Nano** taxonomy in [`bhv.md`](../../bhv.md). The machine-readable catalog is [`configs/mapping.yaml`](../../configs/mapping.yaml). Every event is schema **1.3** and carries:

| Field | Meaning |
|---|---|
| `rule_id` | Nano ID (e.g. `WEB_SHELL_PATTERN`) |
| `macro` / `micro` | e.g. `M1` / `M1.1` |
| `src` | `EBPF-EXEC` \| `EBPF-NET` \| `EBPF-FILE` \| `AUDIT` \| `FIM` \| `PROCSCAN` \| `INVENTORY` |
| `type` | `EVENT` \| `DELTA` \| `STATE` |
| `anchor` | cgroup v2 path or systemd unit (not process name) |
| `conf_band` | `HIGH` \| `MEDIUM` \| `LOW` |
| `confidence` | 0–100 scored via the rule pack |
| `chain_id` / `evidence_loss` | Set when a CHAIN-1…6 correlation fires |

Scoring thresholds live in [`configs/lab_rule_pack.yaml`](../../configs/lab_rule_pack.yaml) (full catalog) and [`configs/rule_pack.example.yaml`](../../configs/rule_pack.example.yaml) (production subset).

## Macro 1 — Persistent command execution via internet-facing apps

| Nano | Notes |
|---|---|
| `WEB_DOCROOT_EXEC_WRITE` | Web-cgroup write of interpretable file under docroot |
| `WEB_SHELL_PATTERN` | Content: **exec primitive + input channel** required; obfuscation is a booster only |
| `WEB_APP_FILE_TAMPER` | Baseline hash drift on web files |
| `WEB_UPLOAD_DIR_EXEC` | Interpretable file under `uploads/`/`tmp/`/`cache/` |
| `WEB_WORKER_RECON_CHILD` | Recon binaries under web unit |
| `WEB_WORKER_SHELL_CHILD` | `sh`/`bash`/`dash`/`zsh` child |
| `WEB_WORKER_INTERP_CHILD` | `python -c` / `perl -e` / `php -r` / … |
| `WEB_WORKER_DOWNLOADER_CHILD` | `curl`/`wget`/`nc`/`socat` |
| `PROC_RARE_ANCESTRY` | Unseen parent→child vs baseline |
| `PROC_SOCKET_STDIO` | Reverse-shell style shell↔socket |
| `PROC_PTY_SPAWN` | PTY upgrade in web context |
| `NETWORK_WEB_WORKER_EGRESS` | Outbound from web worker |
| `NETWORK_IMDS_ACCESS` | `169.254.169.254` / `fd00:ec2::254` |
| `NETWORK_LISTEN_NEW` | New listen in web/host context |
| `YARA_DISK_MATCH` | Non-bhv; mapped under M1.1 |

## Macro 2 — Persistence via admin mechanisms

SSH: `SSH_AUTHKEY_NEW`, `SSH_AUTHKEY_INVALID_LINE`, `SSHD_CONFIG_ANOMALY`, `SSHD_DROPIN_NEW`, `SSHD_FORCED_COMMAND`, `SSH_RC_HOOK`, `SSH_SOCKET_OVERRIDE`, `SSH_HOSTKEY_CHANGE`

Scheduled: `CRON_HIGH_RISK`, `CRON_SPOOL_CHANGE`, `CRON_DROPIN_NEW`, `CRON_RUNPARTS_EVASION`, `SYSTEMD_PERSISTENCE`, `SYSTEMD_USER_PERSISTENCE`, `SYSTEMD_GENERATOR_NEW`, `SYSTEMD_DROPIN_OVERRIDE`, `AT_JOB_NEW`

Identities: `USER_ACCOUNT_ANOMALY`, `USER_PRIV_GROUP_ADD`, `USER_SHELL_ENABLED`, `USER_PASSWD_HASH_CHANGE`, `SUDOERS_PERSISTENCE`, `PAM_PERSISTENCE`, `PAM_CONFIG_PROFILE_NEW`, `NSS_CONFIG_CHANGE`

Ubuntu M2.4: `APT_HOOK_PERSISTENCE`, `MOTD_SCRIPT_NEW`, `PROFILE_HOOK`, `ENVIRONMENT_FILE_CHANGE`, `NETWORK_DISPATCHER_HOOK`, `UDEV_RUN_RULE`, `POLKIT_RULE_NEW`, `NEEDRESTART_HOOK`, `SNAP_DANGEROUS_INSTALL`, `RC_LOCAL_REVIVED`, `INITRAMFS_HOOK`, `GRUB_CMDLINE_CHANGE`, `XDG_AUTOSTART_NEW`, …

## Macro 3 — Privilege escalation & defense weakening

Loader: `LD_SO_PRELOAD_FILE`, `PROC_LD_PRELOAD_ENV`, `LD_SO_CONF_CHANGED`, `LIB_HASH_MISMATCH`, `PROC_MAPPED_UNPACKAGED_LIB`, `LIB_UNPACKAGED_SO`

Privileged context: `SUID_INVENTORY_DELTA`, `SUID_UNPACKAGED`, `SUID_IN_WRITABLE_PATH`, `FILE_CAPABILITY_DELTA`, `PROC_SUDDEN_ROOT`, `GTFOBIN_EXEC`, `USERNS_UNPRIV_CREATE`, `CVE_2026_31431_*` (mapped here)

Defense: `APPARMOR_PROFILE_DISABLED`, `APPARMOR_COMPLAIN_MODE`, `SYSCTL_HARDENING_OFF`, `AUDITD_TAMPER`, `FIREWALL_FLUSH`, `SECURITY_SERVICE_STOP`, `KERNEL_MODULE_LOAD`, `EBPF_PROGRAM_LOAD`, `AGENT_TAMPERED` (mapped here)

## Macro 4 — Concealment

`PROC_DELETED_EXEC_SEGMENT`, `PROC_MEMFD_EXEC`, `PROC_RWX_MEMORY_SEGMENT`, `PROC_WRITABLE_PATH_MAP`, `PROC_UNEXPECTED_TRACER`, `PROC_PTRACE_INJECT`, `PROC_MASQUERADE_NAME`, `EXEC_FROM_TMPFS`, `YARA_PROCESS_MATCH` (mapped), `JOURNAL_VACUUM`, `LOG_TRUNCATE`, `SHELL_HISTORY_TAMPER`, `RSYSLOG_CONFIG_TAMPER`, …

## Macro 5 — Credential access

`SHADOW_READ_ANOMALY`, `SSH_PRIVKEY_ACCESS`, `SSH_AGENT_SOCKET_ABUSE`, `CLOUD_CRED_FILE_ACCESS`, `APP_SECRET_HARVEST`, `PROC_MEM_READ_CROSS_UID`, `CRED_MASS_FILE_ACCESS`

## Macro 6 — Container / virt boundary

`CONTAINER_SOCKET_ACCESS`, `CONTAINER_HOST_MOUNT`, `RUNC_SELF_EXE_WRITE`, `CGROUP_RELEASE_AGENT_WRITE`, `CONTAINER_PRIVILEGED_START`, `LXD_HOST_DISK_ATTACH`, `NS_ESCAPE_SETNS`

## Correlation chains

Ordered, time-windowed, **same-anchor** chains (see `mapping.yaml` `chains:`):

| Chain | Window | Outcome |
|---|---|---|
| CHAIN-1 | 30m | Web RCE → persistence → CRITICAL |
| CHAIN-2 | 10m | Web RCE → IMDS/cloud creds → CRITICAL |
| CHAIN-3 | 15m | Privesc → persistence → CRITICAL |
| CHAIN-4 | 20m | Defense disable → concealment → CRITICAL |
| CHAIN-5 | 10m | Container escape → host → CRITICAL |
| CHAIN-6 | 60m | Any HIGH → log wipe → CRITICAL + `evidence_loss` |

## Anchor rule

Process **names are never the primary anchor**. Prefer systemd unit / cgroup v2 path (`watched_units` in config). `TargetProcessNames` remains a fallback for hosts without readable cgroup metadata.
