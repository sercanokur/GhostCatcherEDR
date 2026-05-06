# Detections

This page lists what GhostCatcher actually catches today, grouped by attack stage. Every detection produces a JSON event with a stable `rule_id`, a MITRE-aligned `technique_id`, a `confidence` score, and one or more `signals[]`. The exact thresholds and weights live in [`configs/rule_pack.example.yaml`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/configs/rule_pack.example.yaml) — this page is the human-readable map.

## Initial access / web layer

### Web shells (PHP, JSP, ASPX, ColdFusion, Perl)

- **Where:** every path under `document_roots`. Extensions covered: `.php`, `.phtml`, `.phar`, `.jsp`, `.jspx`, `.aspx`, `.ashx`, `.cfm`, `.inc`, plus a magic-byte check for files served as images.
- **How:**
  1. Normalize content (strip comments, collapse `"ev"."al"` style concatenation, recursively decode inline base64).
  2. Run a 30+ regex pattern set across the normalized text.
  3. Add corroborating signals: Shannon entropy spike, magic-byte / extension mismatch, `www-data` / `apache` ownership, SUID/SGID bit, tiny-but-high-signal heuristic.
  4. Run the **PHP taint-flow** mini-parser (see below).
- **Rule IDs:** `WEB_SHELL_PATTERN`, `WEB_FILE_NEW`, `WEB_FILE_HASH_DRIFT`, `WEB_TAINT_FLOW`.
- **Techniques:** T1505.003.

### PHP taint flow

- An intraprocedural tokenizer in [`internal/detect/web/php_ast.go`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/internal/detect/web/php_ast.go) tracks assignments from `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_SERVER`, `php://input` into dangerous sinks: `eval`, `assert`, `system`, `exec`, `shell_exec`, `passthru`, `proc_open`, `popen`, `preg_replace` with `/e` modifier, `include` / `require` with a tainted path.
- Adds a high-confidence `WEB_TAINT_FLOW` signal on top of the regex pass.

### Web worker spawning recon / shell

- Detects `whoami`, `id`, `uname`, `ifconfig`, `ip`, `curl`, `wget`, `ss`, `netstat`, `ps`, `cat /etc/passwd`, `bash`, `sh`, `nc` spawned beneath `nginx`, `apache2`, `httpd`, `php-fpm`, `tomcat`, `lighttpd`.
- **Rule IDs:** `WEB_RECON_CHILD`, `WEB_WORKER_SHELL`.
- **Techniques:** T1059.004 / T1059.006.

## Persistence

### SSH

- `~/.ssh/authorized_keys` fingerprint delta vs baseline.
- Invalid-line anomaly (malformed entries used for hiding).
- `sshd_config` and `sshd_config.d` delta — flags `PermitRootLogin yes`, `AuthorizedKeysCommand`, `ForceCommand`, `Match` blocks granting shells.
- **Rule IDs:** `SSH_KEY_NEW`, `SSH_CONFIG_DRIFT`. **Techniques:** T1098.004, T1556.

### Cron and at

- Watches `/etc/crontab`, `/etc/cron.{hourly,daily,weekly,monthly,d}`, `/etc/anacrontab`, `/var/spool/cron/*`, `/var/spool/atjobs`.
- Tokens normalized via a quote-stripping shlex pass and **base64 payloads recursively decoded** before risk matching: `curl`, `wget`, `bash -c`, `sh -c`, `/dev/tcp/`, `nc`, `base64 -d`, `python -c`, `perl -e`, `eval`.
- **Rule IDs:** `CRON_RISK_LINE`, `CRON_FILE_NEW`. **Techniques:** T1053.003.

### systemd

- Walks `/etc/systemd/system`, `/usr/lib/systemd/system`, and per-user units. Detects new or changed `*.service` / `*.timer`, especially with risky `ExecStart*` (curl pipe to shell, base64 decode, network sockets) plus `User=root`.
- **Rule IDs:** `SYSTEMD_UNIT_NEW`, `SYSTEMD_TIMER_NEW`, `SYSTEMD_UNIT_RISK`. **Techniques:** T1053.006.

### Shell init / profile

- `~/.bashrc`, `~/.zshrc`, `~/.profile`, `/etc/profile`, `/etc/profile.d/*`, `/etc/bash.bashrc`, `/etc/zsh/zshenv`, `/etc/zsh/zshrc`.
- Diff vs baseline + high-risk tokens.
- **Rule IDs:** `SHELLRC_DRIFT`. **Techniques:** T1546.004.

### PAM

- `/etc/pam.d/*` delta + module references like `pam_exec.so`, `pam_python.so`, `pam_unix.so` chained with `nullok`.
- **Rule IDs:** `PAM_DRIFT`. **Techniques:** T1556.003.

### sudoers

- `/etc/sudoers` and `/etc/sudoers.d/*` delta.
- High-risk directives: `NOPASSWD`, `!authenticate`, `runas_default=root`, `Defaults targetpw`, world-writable include paths.
- **Rule IDs:** `SUDOERS_DRIFT`. **Techniques:** T1548.003.

### Users

- `/etc/passwd` and `/etc/shadow`: UID 0 non-root accounts, newly added accounts, empty password hashes, locked accounts becoming unlocked.
- **Rule IDs:** `USER_UID0_NEW`, `USER_PASSWORD_EMPTY`. **Techniques:** T1136.001.

### Kernel modules

- `/proc/modules` delta plus drop-in changes under `/etc/modules-load.d`, `/etc/modprobe.d`.
- **Rule IDs:** `KMOD_NEW`, `KMOD_LOADED_NEW`. **Techniques:** T1547.006.

### Dynamic linker

- `LD_PRELOAD` in `/proc/*/environ` for processes you watch.
- `/etc/ld.so.preload` content delta.
- `/etc/ld.so.conf` and `/etc/ld.so.conf.d/*` modifications, especially world-writable paths added.
- **Rule IDs:** `LD_PRELOAD_NEW`, `LD_PRELOAD_FILE`, `LDCONF_DRIFT`. **Techniques:** T1574.006.

## Privilege escalation

### SUID / SGID drift

- Walks `$PATH`-like directories. Alerts on:
  - new SUID or SGID binaries,
  - hash change of a known SUID,
  - SUID binary on a world-writable path.
- **Rule IDs:** `SUID_NEW`, `SUID_HASH_DRIFT`. **Techniques:** T1548.001.

### File capabilities (`security.capability` xattr)

- Reads xattrs of binaries under watched paths and compares against the baseline.
- **Rule IDs:** `CAPS_DRIFT`. **Techniques:** T1548.

## Defense evasion / fileless

### `/proc/[pid]/maps`

- RWX-backed regions with paths under `/dev/shm`, `/tmp`, `/var/tmp`, `/run`, or `(deleted)`.
- Per-process loaded `.so` allowlist baselined at commit; any new `.so` outside the allowlist for a watched comm fires.
- `TracerPid` non-zero on processes that should not be traced.
- `CapEff` escalation vs baseline.
- **Rule IDs:** `MAPS_RWX`, `MAPS_DELETED`, `MAPS_SO_NEW`, `PROC_TRACED`, `CAPEFF_ESCALATION`. **Techniques:** T1055, T1620, T1014.

### Reflective load / memfd

- Realtime sensor catches `memfd_create` followed by exec of an `/proc/self/fd/*` path; debounces a `/proc/maps` rescan to confirm.
- **Rule IDs:** `MEMFD_EXEC`. **Techniques:** T1055.001.

### Agent self-tampering

- The selfguard goroutine re-hashes the agent binary every `selfguard.check_interval`. Any drift emits a critical event and (if running under systemd notify) stops sending watchdog pings, which restarts the unit.
- **Rule IDs:** `AGENT_TAMPERED`. **Techniques:** T1562.001.

## Integrity

- Distro-aware: `/etc/os-release` selects between `dpkg --verify` (Debian/Ubuntu) and `rpm -Va` (RHEL/CentOS/Fedora) for `integrity_paths`.
- TOCTOU-safe: file is `open()`ed once, the file descriptor is `fstat`ed and hashed off the same fd.
- **Rule IDs:** `INTEGRITY_DRIFT`, `INTEGRITY_MISSING`. **Techniques:** T1036.

## Process behavior

### Rare ancestry

- At baseline commit, a graph of `(parent_comm, child_comm)` pairs is recorded. At runtime any pair where the parent is "juicy" (`nginx`, `httpd`, `apache2`, `php-fpm`, `sshd`, `mysqld`, `cron`, `systemd-journald`, …) and the child is `sh`/`bash`/`nc`/`curl`/`wget`/`python`/`perl`/`ruby`/`socat` and the pair was not seen at baseline emits.
- **Rule IDs:** `PROC_RARE_ANCESTRY`. **Techniques:** T1059.

## Network

- `/proc/net/tcp`, `tcp6`, `udp`, `udp6` parsed and joined to `/proc/*/fd` socket inodes to attribute every socket to a process.
- Three classes of detection:
  - **Reverse shell hint** — a shell-like comm (`sh`, `bash`, `nc`, `socat`, `python`) holding an outbound TCP socket to a non-allowlisted public IP.
  - **Unexpected listen** — a process listening on a port not in baseline.
  - **Web worker egress** — `nginx`/`php-fpm`/`tomcat`/`apache2` opening outbound to anything outside `network_allow_cidrs`.
- **Rule IDs:** `NET_REVERSE_SHELL`, `NET_LISTEN_NEW`, `NET_WEB_EGRESS`. **Techniques:** T1571, T1041, T1071.001.

## YARA (optional, with_yara build)

- Disk scan across `document_roots` and any extra path supplied via the rule pack.
- Live process memory scan for processes whose `comm` matches the YARA-watched set.
- Each match is one event with the YARA rule `meta` carried over to `evidence`.
- **Rule IDs:** `YARA_DISK`, `YARA_MEMORY`. **Techniques:** depend on the rule's `meta.technique`.

## IOC enrichment

- Every event passes through enrichment. If a file hash matches a hash feed entry, confidence gets +10 and an `ioc_matches[]` entry is added. If a remote IP, CIDR, or domain matches, confidence gets +25.
- See **[Configuration](Configuration)** for `ioc_feed_dir` layout.

## Container context

- Reads `/proc/[pid]/cgroup` and classifies Docker, containerd, cri-o, Kubernetes (Pod UID), and LXC. Sets `container.runtime`, `container.id`, and where available `container.pod_uid`.

## Severity scale

- **info** — informational, never alert by itself.
- **low** — single weak signal; collected for hunting.
- **medium** — multi-signal pattern with at least one strong indicator.
- **high** — a rule with `min_signals` met and the optional `expr` true; alerts when above `min_confidence_for_alert`.
- **critical** — high-confidence destructive or evasive activity (e.g. agent tamper, memfd exec, reverse shell to public IP).

Continue to **[Sensors](Sensors)** to understand where the raw evidence comes from.
