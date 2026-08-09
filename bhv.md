# GhostCatcher — Ubuntu Behavior Tree (v2)

Scope: Ubuntu 20.04 / 22.04 / 24.04 LTS (server + cloud image).
Goal: define the Macro → Micro → Nano taxonomy together with the field set
(source, type, anchor, confidence, FP) needed to port it straight into a
detection engine.

---

## 0. Field Dictionary (required for every nano)

| Field | Meaning | Allowed values |
|---|---|---|
| `src` | Telemetry source | `EBPF-EXEC`, `EBPF-NET`, `EBPF-FILE`, `AUDIT`, `FIM`, `PROCSCAN`, `INVENTORY` |
| `type` | Detection type | `EVENT` (syscall stream), `DELTA` (baseline diff), `STATE` (periodic snapshot) |
| `anchor` | Context anchor | cgroup v2 path / systemd unit / UID / mount ns |
| `conf` | Standalone confidence | `HIGH` / `MEDIUM` / `LOW` (LOW = correlation only) |
| `fp` | Known Ubuntu noise | free text |

**Core rule:** a process *name* is never the primary anchor. The primary anchor
is the `cgroup v2` path or `_SYSTEMD_UNIT` (`nginx` can be renamed;
`/system.slice/nginx.service` cannot easily be).

**Provenance rule:** every file-based nano is enriched with `dpkg -S` /
`dpkg --verify` results. "New SUID file" is medium confidence; "SUID file owned
by no package" is high confidence.

---

## Macro 1 — Persistent command execution via an internet-facing application

**MITRE:** T1190, T1505.003, T1059.004, T1059.006, T1071.001, T1552.005

### M1.1 — Web shell drop / backdooring an existing application file

| ID | Nano | src | type | conf |
|---|---|---|---|---|
| `WEB_DOCROOT_EXEC_WRITE` | Process in a web service cgroup wrote interpretable content under docroot (`.php`, `.jsp`, `.jspx`, `.phar`, `.aspx`, `.py`, `.cgi`) | `EBPF-FILE` | EVENT | HIGH |
| `WEB_SHELL_PATTERN` | Written/modified file combines dangerous functions with obfuscation | `FIM` | STATE | MEDIUM |
| `WEB_APP_FILE_TAMPER` | Hash changed on a file managed by a package or VCS | `INVENTORY` | DELTA | MEDIUM |
| `WEB_UPLOAD_DIR_EXEC` | Executable extension appeared in an upload directory (`uploads/`, `tmp/`, `cache/`) | `FIM` | DELTA | HIGH |

**Ubuntu docroot paths:** `/var/www/html`, `/usr/share/nginx/html`, `/srv/www`,
`/var/lib/tomcat9|tomcat10/webapps`, `/opt/*/public`, `/var/snap/*/current/*`
(snap-installed nextcloud/wordpress etc.).

**Pattern set (`WEB_SHELL_PATTERN`) — require a language-independent combination:**
- Execution primitive: `eval`, `assert`, `system`, `exec`, `shell_exec`, `passthru`,
  `popen`, `proc_open`, `preg_replace(/e)`, `create_function`,
  `Runtime.getRuntime().exec`, `ProcessBuilder`, `__import__("os")`
- Input channel: `$_REQUEST`, `$_POST`, `$_GET`, `$_COOKIE`, `php://input`,
  `request.getParameter`
- Obfuscation: `base64_decode`, `gzinflate`, `str_rot13`, `hex2bin`, `chr()` chains,
  high entropy (>4.5 bits/byte) + low comment ratio

> Never write a standalone "contains base64" rule — WordPress plugins, Composer
> vendor directories and minified JS trip it constantly. **Execution primitive +
> input channel** are mandatory; obfuscation is only a score booster.

**fp:** `wp-content/plugins/*` updates, `composer install`, `vendor/` rewrites,
Laravel `storage/framework/views/` cache files, CI/CD deploys (rsync/git pull) —
allowlist these by unit/UID.

### M1.2 — System reconnaissance or command execution via a web worker

| ID | Nano | src | type | conf |
|---|---|---|---|---|
| `WEB_WORKER_RECON_CHILD` | Recon binary spawned from a web cgroup: `id`, `whoami`, `uname`, `hostname`, `ip`, `ss`, `netstat`, `ps`, `find`, `cat /etc/passwd` | `EBPF-EXEC` | EVENT | HIGH |
| `WEB_WORKER_SHELL_CHILD` | `sh`/`bash`/`dash`/`zsh` child from a web cgroup | `EBPF-EXEC` | EVENT | HIGH |
| `WEB_WORKER_INTERP_CHILD` | Interpreter child with `-c` / `-e` / `-r` flags from a web cgroup (`python3 -c`, `perl -e`, `php -r`, `ruby -e`, `node -e`) | `EBPF-EXEC` | EVENT | HIGH |
| `WEB_WORKER_DOWNLOADER_CHILD` | `curl`, `wget`, `nc`, `socat`, `ftp`, `tftp`, `busybox wget` child from a web cgroup | `EBPF-EXEC` | EVENT | HIGH |
| `PROC_RARE_ANCESTRY` | (parent unit, child binary) pair unseen in the 30-day baseline | `EBPF-EXEC` | DELTA | MEDIUM |
| `PROC_SOCKET_STDIO` | Process fd 0/1/2 point to `socket:[...]` and its ancestor is a web unit → reverse shell | `PROCSCAN` | STATE | HIGH |
| `PROC_PTY_SPAWN` | TTY upgrade in web context via `openpty`/`script -qc`/`python pty.spawn` | `EBPF-EXEC` | EVENT | HIGH |

**Version note — worker names:**
- 20.04: `php-fpm7.4`, `apache2`, `nginx`, `uwsgi`
- 22.04: `php-fpm8.1`, `gunicorn`, `node`
- 24.04: `php-fpm8.3`
Keep a **watched unit list** instead of a regex; the `.service` name is
version-independent.

**fp:** `logrotate` postrotate scripts, `certbot --nginx` renewals, Nagios/Zabbix
`check_*` plugins, legitimate applications that call `exec()`
(ImageMagick/ffmpeg invocations — allowlist by binary name separately).

### M1.3 — External network access from application context

| ID | Nano | src | type | conf |
|---|---|---|---|---|
| `NETWORK_WEB_WORKER_EGRESS` | Outbound connection from a web worker to a public IP outside baseline | `EBPF-NET` | DELTA | MEDIUM |
| `NETWORK_IMDS_ACCESS` | Web worker reaching `169.254.169.254` or `fd00:ec2::254` | `EBPF-NET` | EVENT | HIGH |
| `NETWORK_LISTEN_NEW` | Process in web context started listening on a new port (bind+listen) | `EBPF-NET` | DELTA | HIGH |
| `NETWORK_RAW_IP_NO_DNS` | TCP connection straight to an IP with no preceding DNS resolution | `EBPF-NET` | EVENT | MEDIUM |
| `NETWORK_BEACON_PERIODIC` | Low-jitter periodic connections to the same destination (>10 samples) | `EBPF-NET` | STATE | MEDIUM |

> Always separate `NETWORK_IMDS_ACCESS` from generic egress. On a cloud instance
> with IMDSv1 enabled, this single signal is the highest-fidelity point in the
> SSRF → role credential theft chain (T1552.005).

**fp:** the application's legitimate outbound API calls (Stripe, S3, SMTP relay),
`apt` proxy, `snapd` refresh. Keep the baseline at **destination ASN/domain**
level, not IP level — CDN IPs rotate constantly.

---

## Macro 2 — Persistence by abusing legitimate administration mechanisms

**MITRE:** T1098.004, T1053.003, T1053.006, T1543.002, T1543.003, T1136.001,
T1546.004, T1546.016, T1548.003, T1556.003

### M2.1 — Making SSH access persistent

| ID | Nano | src | type | conf |
|---|---|---|---|---|
| `SSH_AUTHKEY_NEW` | Fingerprint change in `~/.ssh/authorized_keys` or `authorized_keys2` | `FIM` | DELTA | MEDIUM |
| `SSH_AUTHKEY_INVALID_LINE` | Invalid/malformed key line, excessively long `command=` or `environment=` option | `FIM` | STATE | HIGH |
| `SSHD_CONFIG_ANOMALY` | `PermitRootLogin`, `PasswordAuthentication`, `AuthorizedKeysFile`, `PermitTunnel`, `GatewayPorts` changed in a risky direction | `FIM` | DELTA | HIGH |
| `SSHD_DROPIN_NEW` | **New/modified file under `/etc/ssh/sshd_config.d/*.conf`** | `FIM` | DELTA | HIGH |
| `SSHD_FORCED_COMMAND` | `ForceCommand` or `AuthorizedKeysCommand` added/changed | `FIM` | DELTA | HIGH |
| `SSH_RC_HOOK` | `/etc/ssh/sshrc` or `~/.ssh/rc` created/modified | `FIM` | DELTA | HIGH |
| `SSH_SOCKET_OVERRIDE` | Override on the `ssh.socket` unit (24.04 socket activation) | `FIM` | DELTA | HIGH |
| `SSH_HOSTKEY_CHANGE` | Unexpected change to `/etc/ssh/ssh_host_*` | `FIM` | DELTA | MEDIUM |

> **Critical gap:** on Ubuntu 22.04+, `sshd_config` **starts** with
> `Include /etc/ssh/sshd_config.d/*.conf`. A rule that watches only the main file
> is blind to every change made through a drop-in. On 24.04, `ssh.socket` is also
> active; overriding `ssh.service` alone is not enough.

**fp:** `cloud-init` writes `authorized_keys` on first boot (first boot only —
correlate with `/var/lib/cloud/instance/boot-finished`), Ansible `authorized_key`
module, the `50-cloud-init.conf` drop-in (present by default; allowlist when its
creation time matches first boot).

### M2.2 — Re-execution via scheduled tasks

| ID | Nano | src | type | conf |
|---|---|---|---|---|
| `CRON_HIGH_RISK` | Cron entry with encoded payload (`base64 -d`, `echo\|sh`), network fetch (`curl\|bash`), or `/tmp`,`/dev/shm`,`/var/tmp` paths | `FIM` | DELTA | HIGH |
| `CRON_SPOOL_CHANGE` | Change in **`/var/spool/cron/crontabs/<user>`** (Debian path — not RedHat's `/var/spool/cron/`) | `FIM` | DELTA | MEDIUM |
| `CRON_DROPIN_NEW` | New file in `/etc/cron.d/`, `/etc/cron.{hourly,daily,weekly,monthly}/`, `/etc/crontab` | `FIM` | DELTA | MEDIUM |
| `CRON_RUNPARTS_EVASION` | Name that `run-parts` will **not** execute (contains a dot, ends in `~`) but has the exec bit set — anti-forensic indicator | `FIM` | STATE | MEDIUM |
| `SYSTEMD_PERSISTENCE` | New/modified `.service` or `.timer`; suspicious `ExecStart` path or encoded command | `FIM` | DELTA | HIGH |
| `SYSTEMD_USER_PERSISTENCE` | **`~/.config/systemd/user/*.service` + `loginctl enable-linger`** — rootless, reboot-surviving persistence | `FIM` | DELTA | HIGH |
| `SYSTEMD_GENERATOR_NEW` | New binary under `/etc/systemd/system-generators/` or `/usr/lib/systemd/system-generators/` | `FIM` | DELTA | HIGH |
| `SYSTEMD_DROPIN_OVERRIDE` | Override for an existing unit at `/etc/systemd/system/<unit>.d/*.conf` | `FIM` | DELTA | MEDIUM |
| `AT_JOB_NEW` | New job under `/var/spool/cron/atjobs/` | `FIM` | DELTA | MEDIUM |

**systemd paths to watch:** `/etc/systemd/system/`, `/usr/lib/systemd/system/`,
`/run/systemd/system/`, `/etc/systemd/user/`, `~/.config/systemd/user/`,
`/lib/systemd/system-sleep/`, `/lib/systemd/system-shutdown/`.

**fp:** `apt-daily.timer`, `apt-daily-upgrade.timer`, `motd-news.timer`,
`fwupd-refresh.timer`, `snapd.refresh.timer`, `logrotate.timer`, `man-db.timer`,
`e2scrub_all.timer`, `ua-timer.timer` (Ubuntu Pro),
`update-notifier-download.timer`. These are distribution defaults — verify
package ownership with `dpkg -S` and allowlist.

### M2.3 — Abuse of privileged identities and configuration

| ID | Nano | src | type | conf |
|---|---|---|---|---|
| `USER_ACCOUNT_ANOMALY` | New UID 0 account, or an existing account's UID changed to 0 | `FIM` | DELTA | HIGH |
| `USER_PRIV_GROUP_ADD` | Member added to **`sudo`, `admin`, `lxd`, `docker`, `microk8s`, `adm`, `disk`, `shadow`** | `FIM` | DELTA | HIGH |
| `USER_SHELL_ENABLED` | Service account's shell changed from `nologin`/`false` to a real shell | `FIM` | DELTA | HIGH |
| `USER_PASSWD_HASH_CHANGE` | Unexpected hash change or empty password field in `/etc/shadow` | `FIM` | DELTA | MEDIUM |
| `SUDOERS_PERSISTENCE` | `NOPASSWD:ALL`, `!authenticate`, or removal of `Defaults targetpw` in `/etc/sudoers` or `/etc/sudoers.d/*` | `FIM` | DELTA | HIGH |
| `PAM_PERSISTENCE` | New module line or `pam_permit`/`pam_exec` added in `/etc/pam.d/*` | `FIM` | DELTA | HIGH |
| `PAM_CONFIG_PROFILE_NEW` | **New profile under `/usr/share/pam-configs/`** (auto-merged into `common-auth` by `pam-auth-update` — quieter than direct edits) | `FIM` | DELTA | HIGH |
| `PAM_MODULE_UNPACKAGED` | `.so` under `/lib/x86_64-linux-gnu/security/` owned by no package | `INVENTORY` | DELTA | HIGH |
| `NSS_CONFIG_CHANGE` | New/unknown service module in `/etc/nsswitch.conf` | `FIM` | DELTA | HIGH |

> **The `lxd` and `docker` groups are root-equivalent in practice.** Since LXD
> ships by default on Ubuntu, tying `USER_ACCOUNT_ANOMALY` to UID 0 alone leaves
> a major gap.

### M2.4 — Ubuntu-specific persistence surfaces *(new micro)*

| ID | Nano | src | type | conf |
|---|---|---|---|---|
| `APT_HOOK_PERSISTENCE` | `DPkg::Pre-Invoke` / `Post-Invoke` / `APT::Update::Pre-Invoke` in `/etc/apt/apt.conf.d/*` — root execution on every apt operation | `FIM` | DELTA | HIGH |
| `DPKG_TRIGGER_HOOK` | Unpackaged modification to `/var/lib/dpkg/info/*.postinst` | `INVENTORY` | DELTA | HIGH |
| `MOTD_SCRIPT_NEW` | New/modified script in `/etc/update-motd.d/` — **runs on every SSH session** | `FIM` | DELTA | HIGH |
| `PROFILE_HOOK` | Changes to `/etc/profile`, `/etc/profile.d/*`, `/etc/bash.bashrc`, `~/.bashrc`, `~/.bash_profile`, `~/.bash_logout` | `FIM` | DELTA | MEDIUM |
| `ENVIRONMENT_FILE_CHANGE` | Execution-relevant change in `/etc/environment` or `/etc/default/*` | `FIM` | DELTA | MEDIUM |
| `NETWORK_DISPATCHER_HOOK` | `/etc/networkd-dispatcher/*/`, `/etc/NetworkManager/dispatcher.d/`, `/etc/network/if-up.d/` | `FIM` | DELTA | HIGH |
| `UDEV_RUN_RULE` | New rule containing `RUN+=` in `/etc/udev/rules.d/` | `FIM` | DELTA | HIGH |
| `POLKIT_RULE_NEW` | `/etc/polkit-1/rules.d/*.rules` — altering authorization decisions via JavaScript | `FIM` | DELTA | HIGH |
| `NEEDRESTART_HOOK` | New Perl config under `/etc/needrestart/conf.d/` | `FIM` | DELTA | HIGH |
| `SNAP_DANGEROUS_INSTALL` | Unsigned snap via `snap install --dangerous` / `--devmode` / `--classic` | `EBPF-EXEC` | EVENT | HIGH |
| `SNAP_HOOK_NEW` | Executable under `/snap/*/current/meta/hooks/` or `/var/snap/*/current/` | `FIM` | DELTA | MEDIUM |
| `RC_LOCAL_REVIVED` | `/etc/rc.local` created + exec bit (absent by default on modern Ubuntu) | `FIM` | DELTA | HIGH |
| `INITRAMFS_HOOK` | Change under `/etc/initramfs-tools/hooks/` or `scripts/` | `FIM` | DELTA | HIGH |
| `GRUB_CMDLINE_CHANGE` | Parameters like `init=`, `apparmor=0`, `selinux=0` in `/etc/default/grub` | `FIM` | DELTA | HIGH |
| `XDG_AUTOSTART_NEW` | `~/.config/autostart/*.desktop`, `/etc/xdg/autostart/` (desktop installs) | `FIM` | DELTA | MEDIUM |

**fp:** `unattended-upgrades` writes `apt.conf.d/50unattended-upgrades`,
`landscape-common` installs a motd script, `ubuntu-advantage-tools` (Pro) adds
both an apt hook and a motd script, `update-notifier` ships
`90-updates-available`. All of these are **package-owned** — `dpkg -S`
verification cuts FPs by roughly 95%.

---

## Macro 3 — Privilege escalation and defense weakening

**MITRE:** T1574.006, T1548.001, T1068, T1055, T1562.001, T1562.006, T1547.006

### M3.1 — Dynamic loader / library injection

| ID | Nano | src | type | conf |
|---|---|---|---|---|
| `LD_SO_PRELOAD_FILE` | `/etc/ld.so.preload` created/modified (**does not exist** by default on Ubuntu) | `FIM` | DELTA | HIGH |
| `PROC_LD_PRELOAD_ENV` | `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH` in process environment (especially on setuid binary invocation) | `PROCSCAN` | STATE | MEDIUM |
| `LD_SO_CONF_CHANGED` | `/etc/ld.so.conf` or `/etc/ld.so.conf.d/*.conf` changed; world-writable path added | `FIM` | DELTA | HIGH |
| `LIB_UNPACKAGED_SO` | `.so` in system library directories (`/lib`, `/usr/lib`, `/lib/x86_64-linux-gnu`) owned by no package | `INVENTORY` | DELTA | HIGH |
| `LIB_HASH_MISMATCH` | Package file showing a hash mismatch under `dpkg --verify` | `INVENTORY` | DELTA | HIGH |
| `PROC_MAPPED_UNPACKAGED_LIB` | Running process has mapped an unpackaged or deleted `.so` | `PROCSCAN` | STATE | HIGH |

### M3.2 — Creating a privileged execution context

| ID | Nano | src | type | conf |
|---|---|---|---|---|
| `SUID_INVENTORY_DELTA` | New SUID/SGID file | `INVENTORY` | DELTA | MEDIUM |
| `SUID_UNPACKAGED` | SUID/SGID file **owned by no package** | `INVENTORY` | DELTA | HIGH |
| `SUID_IN_WRITABLE_PATH` | SUID file under `/tmp`, `/var/tmp`, `/dev/shm`, `/home` | `INVENTORY` | DELTA | HIGH |
| `FILE_CAPABILITY_DELTA` | New binary carrying `cap_setuid`, `cap_sys_admin`, `cap_dac_read_search`, `cap_sys_ptrace`, `cap_bpf`, `cap_sys_module` | `INVENTORY` | DELTA | HIGH |
| `PROC_SUDDEN_ROOT` | Non-root → root transition with no known privesc path (sudo/su/polkit session) | `EBPF-EXEC` | EVENT | HIGH |
| `GTFOBIN_EXEC` | GTFOBins pattern: `find -exec`, `vim -c :!`, `awk 'BEGIN{system()}'`, `tar --checkpoint-action=exec`, `env sh` — especially in sudo/SUID context | `EBPF-EXEC` | EVENT | MEDIUM |
| `USERNS_UNPRIV_CREATE` | Unprivileged user created a namespace via `CLONE_NEWUSER` (bypass indicator for the 23.10+ AppArmor restriction) | `EBPF-EXEC` | EVENT | MEDIUM |

**Ubuntu SUID baseline** (these are normal; use as the delta reference):
`/usr/bin/sudo`, `/usr/bin/passwd`, `/usr/bin/chsh`, `/usr/bin/chfn`,
`/usr/bin/gpasswd`, `/usr/bin/newgrp`, `/usr/bin/su`, `/usr/bin/mount`,
`/usr/bin/umount`, `/usr/bin/pkexec`, `/usr/bin/fusermount3`,
`/usr/lib/openssh/ssh-keysign`, `/usr/lib/dbus-1.0/dbus-daemon-launch-helper`,
`/usr/lib/policykit-1/polkit-agent-helper-1`, `/usr/libexec/snap-confine` (24.04)
or `/usr/lib/snapd/snap-confine` (≤22.04).

### M3.3 — Weakening defensive mechanisms *(new micro — Ubuntu's distinguishing signal)*

| ID | Nano | src | type | conf |
|---|---|---|---|---|
| `APPARMOR_PROFILE_DISABLED` | Symlink into `/etc/apparmor.d/disable/` or an `apparmor_parser -R` call | `FIM` + `EBPF-EXEC` | EVENT | HIGH |
| `APPARMOR_COMPLAIN_MODE` | `aa-complain` / `aa-disable` executed, or a profile moved enforce→complain | `EBPF-EXEC` | EVENT | HIGH |
| `APPARMOR_USERNS_RESTRICT_OFF` | `kernel.apparmor_restrict_unprivileged_userns` → 0 (23.10+/24.04) | `AUDIT` | DELTA | HIGH |
| `SYSCTL_HARDENING_OFF` | `kernel.yama.ptrace_scope`→0, `kernel.dmesg_restrict`→0, `kernel.kptr_restrict`→0, `kernel.unprivileged_bpf_disabled`→0, `fs.protected_hardlinks`→0 | `AUDIT` | DELTA | HIGH |
| `AUDITD_TAMPER` | `auditctl -e 0`, `auditctl -D`, emptying `/etc/audit/rules.d/`, stopping `auditd` | `AUDIT` | EVENT | HIGH |
| `FIREWALL_FLUSH` | `ufw disable`, `iptables -F`, `nft flush ruleset` | `EBPF-EXEC` | EVENT | MEDIUM |
| `SECURITY_SERVICE_STOP` | Stopping/masking `apparmor`, `auditd`, `ufw`, `fail2ban`, `snapd.apparmor` units | `AUDIT` | EVENT | HIGH |
| `KERNEL_MODULE_LOAD` | `init_module`/`finit_module` with an unsigned or unpackaged module; changes to `/etc/modules-load.d/` | `AUDIT` | EVENT | HIGH |
| `EBPF_PROGRAM_LOAD` | Off-baseline process loaded a kprobe/tracepoint/XDP program via `bpf(BPF_PROG_LOAD)` | `AUDIT` | EVENT | MEDIUM |

> Setting `kernel.yama.ptrace_scope` to 0 is a **precondition** for
> `PROC_UNEXPECTED_TRACER` in M4 and the memory-reading techniques in M5. Link
> these signals sequentially in a correlation rule.

**fp:** `docker`/`lxd` installation rewrites iptables rules, DKMS module builds
emit `finit_module`, `libvirt` changes sysctls, `snapd` continuously reloads its
own AppArmor profiles (`snapd.apparmor.service` — allowlist by parent unit).

---

## Macro 4 — Hiding memory/process traces and cleaning up evidence

**MITRE:** T1055, T1620, T1070.002, T1070.004, T1070.006, T1036.005, T1014

### M4.1 — Fileless / anti-forensic execution

| ID | Nano | src | type | conf |
|---|---|---|---|---|
| `PROC_DELETED_EXEC_SEGMENT` | `/proc/<pid>/exe` → `(deleted)`, or a deleted executable segment in maps | `PROCSCAN` | STATE | HIGH |
| `PROC_MEMFD_EXEC` | `/proc/<pid>/exe` → `/memfd:...` — fileless execution via `memfd_create` + `fexecve` | `PROCSCAN` | STATE | HIGH |
| `PROC_RWX_MEMORY_SEGMENT` | Anonymous RWX mapping (especially in non-JIT processes) | `PROCSCAN` | STATE | MEDIUM |
| `PROC_WRITABLE_PATH_MAP` | Executable mapped from a world-writable path or `/tmp`,`/dev/shm` | `PROCSCAN` | STATE | HIGH |
| `PROC_UNEXPECTED_TRACER` | `TracerPid` ≠ 0 in `/proc/<pid>/status` and the tracer is not an expected debugger | `PROCSCAN` | STATE | HIGH |
| `PROC_PTRACE_INJECT` | `ptrace(POKETEXT/POKEDATA/ATTACH)` + `process_vm_writev` against another UID's process | `AUDIT` | EVENT | HIGH |
| `PROC_MASQUERADE_NAME` | `comm` / `argv[0]` disagrees with the real `/proc/<pid>/exe` path; kernel-thread impersonation (`[kworker/...]`) while `exe` exists | `PROCSCAN` | STATE | HIGH |
| `PROC_HIDDEN_PID` | Discrepancy between `/proc` listing and `getdents` / kernel count → LKM rootkit | `PROCSCAN` | STATE | HIGH |
| `EXEC_FROM_TMPFS` | Execution from `/tmp`, `/var/tmp`, `/dev/shm`, `/run/user/*` | `EBPF-EXEC` | EVENT | MEDIUM |

**fp:** JVM/V8/LuaJIT/Wine JITs produce RWX (allowlist by unit), `snapd` and
AppImage execute from `/tmp`, and during `dpkg` upgrades running processes
briefly show a `(deleted)` exe — correlate `PROC_DELETED_EXEC_SEGMENT` with the
last `apt`/`dpkg` transaction time.

### M4.2 — Log and timestamp manipulation *(new micro)*

| ID | Nano | src | type | conf |
|---|---|---|---|---|
| `JOURNAL_VACUUM` | `journalctl --vacuum-*`, `--rotate`, or deletion of `/var/log/journal/*` | `AUDIT` | EVENT | HIGH |
| `LOG_TRUNCATE` | `/var/log/{auth.log,syslog,wtmp,btmp,lastlog,dpkg.log}` truncated or deleted | `FIM` | EVENT | HIGH |
| `SHELL_HISTORY_TAMPER` | `~/.bash_history` symlinked to `/dev/null`, `HISTFILE=` emptied, `unset HISTFILE`, `history -c` | `FIM` + `EBPF-EXEC` | EVENT | MEDIUM |
| `TIMESTOMP_INCONSISTENCY` | `mtime < ctime` inconsistency, or mtime that is an outlier versus neighbouring inodes | `FIM` | STATE | MEDIUM |
| `RSYSLOG_CONFIG_TAMPER` | Removal of a remote log destination in `/etc/rsyslog.conf` or `/etc/rsyslog.d/*` | `FIM` | DELTA | HIGH |

**fp:** `logrotate` runs daily and rotates `wtmp`/`btmp` — separate it by
anchoring on the `logrotate.service` cgroup. `journalctl --vacuum-size` is
legitimate disk maintenance; check whether it came from an interactive TTY or a
maintenance unit.

---

## Macro 5 — Credential access *(new macro)*

**MITRE:** T1003.008, T1552.001, T1552.004, T1552.005, T1555, T1563.001

| Micro | ID | Nano | src | conf |
|---|---|---|---|---|
| System hashes | `SHADOW_READ_ANOMALY` | Reads of `/etc/shadow` or `/etc/gshadow`, or execution of `unshadow`, from outside expected units | `AUDIT` | HIGH |
| SSH keys | `SSH_PRIVKEY_ACCESS` | Reads of `~/.ssh/id_*`, `/etc/ssh/ssh_host_*_key` by a non-owner UID | `AUDIT` | HIGH |
| Agent hijack | `SSH_AGENT_SOCKET_ABUSE` | Connecting to another user's `SSH_AUTH_SOCK` (`/tmp/ssh-*/agent.*`) | `EBPF-NET` | HIGH |
| Cloud identity | `CLOUD_CRED_FILE_ACCESS` | Reads of `~/.aws/credentials`, `~/.config/gcloud/`, `~/.azure/`, `~/.kube/config`, `/var/lib/kubelet/` | `AUDIT` | HIGH |
| App secrets | `APP_SECRET_HARVEST` | Bulk reads of `.env`, `wp-config.php`, `settings.py`, `application.properties`, `/etc/mysql/debian.cnf` | `AUDIT` | MEDIUM |
| Memory | `PROC_MEM_READ_CROSS_UID` | `process_vm_readv` or `/proc/<pid>/mem` reads against a different UID's process (sshd, gnome-keyring, agent) | `AUDIT` | HIGH |
| Mass scan | `CRED_MASS_FILE_ACCESS` | Access to many key/secret files in a short window (>N/60s) | `AUDIT` | MEDIUM |

**fp:** backup agents (restic, borg, duplicity, veeam) and `updatedb`/`plocate`
walk the whole filesystem. Allowlist `plocate.service` and backup units by
anchor; otherwise `CRED_MASS_FILE_ACCESS` fires every night.

---

## Macro 6 — Container / virtualization boundary violation *(new macro)*

**MITRE:** T1610, T1611, T1613, T1552.007

| Micro | ID | Nano | src | conf |
|---|---|---|---|---|
| Socket abuse | `CONTAINER_SOCKET_ACCESS` | Access to `/var/run/docker.sock`, `/run/containerd/containerd.sock`, `/var/snap/lxd/common/lxd/unix.socket` from an unexpected cgroup | `EBPF-FILE` | HIGH |
| Escape | `CONTAINER_HOST_MOUNT` | Mounting `/` or a host device from inside a container; `nsenter --target 1` | `AUDIT` | HIGH |
| Escape | `RUNC_SELF_EXE_WRITE` | Write attempt against `/proc/self/exe` (CVE-2019-5736 class) | `AUDIT` | HIGH |
| Escape | `CGROUP_RELEASE_AGENT_WRITE` | `notify_on_release` + `release_agent` write (cgroup v1 escape) | `EBPF-FILE` | HIGH |
| Privileged | `CONTAINER_PRIVILEGED_START` | Container started with `--privileged`, `--pid=host`, `--net=host`, `-v /:/host`, `--cap-add=SYS_ADMIN` | `EBPF-EXEC` | MEDIUM |
| LXD | `LXD_HOST_DISK_ATTACH` | `lxc config device add ... disk source=/` — the most common LXD privesc path on Ubuntu | `EBPF-EXEC` | HIGH |
| Namespace | `NS_ESCAPE_SETNS` | Transition into the host PID/mount namespace via `setns()` | `AUDIT` | HIGH |

> LXD ships installed by default on Ubuntu, and `lxd` group membership is a
> documented root path. This macro is not optional for Ubuntu.

---

## 7. Correlation Chains (instead of OR-ing nanos)

Individually medium/low-confidence nanos become high confidence in a chain.
Recommended rule form: **ordered + time-windowed + same anchor**.

```
CHAIN-1  Web RCE → persistence          (window: 30 min, anchor: web cgroup + host)
  WEB_DOCROOT_EXEC_WRITE
    → WEB_WORKER_SHELL_CHILD | WEB_WORKER_INTERP_CHILD
      → WEB_WORKER_DOWNLOADER_CHILD | NETWORK_LISTEN_NEW
        → CRON_HIGH_RISK | SYSTEMD_PERSISTENCE | SSH_AUTHKEY_NEW
  Score: CRITICAL

CHAIN-2  Web RCE → cloud credentials    (window: 10 min)
  WEB_WORKER_INTERP_CHILD
    → NETWORK_IMDS_ACCESS
      → CLOUD_CRED_FILE_ACCESS | NETWORK_WEB_WORKER_EGRESS
  Score: CRITICAL

CHAIN-3  Privesc → persistence          (window: 15 min, anchor: process tree)
  PROC_SUDDEN_ROOT | GTFOBIN_EXEC | SUID_UNPACKAGED
    → USER_PRIV_GROUP_ADD | SUDOERS_PERSISTENCE | PAM_CONFIG_PROFILE_NEW
  Score: CRITICAL

CHAIN-4  Defense disable → concealment  (window: 20 min)
  SYSCTL_HARDENING_OFF | APPARMOR_PROFILE_DISABLED | AUDITD_TAMPER
    → PROC_UNEXPECTED_TRACER | PROC_MEM_READ_CROSS_UID | KERNEL_MODULE_LOAD
  Score: CRITICAL

CHAIN-5  Container escape → host        (window: 10 min, anchor: mount ns transition)
  CONTAINER_SOCKET_ACCESS | LXD_HOST_DISK_ATTACH
    → NS_ESCAPE_SETNS | CONTAINER_HOST_MOUNT
      → (any M2 nano in the host ns)
  Score: CRITICAL

CHAIN-6  End-of-operation cleanup       (window: 60 min)
  (any HIGH nano)
    → JOURNAL_VACUUM | LOG_TRUNCATE | SHELL_HISTORY_TAMPER | TIMESTOMP_INCONSISTENCY
  Score: CRITICAL + "evidence loss" flag
```

---

## 8. Baseline and Telemetry Notes

**Baseline source — critical:** build the baseline from a golden image or a
`dpkg --get-selections` + `dpkg --verify` manifest, **not** from a live host.
Learning from a live host risks accepting a post-compromise state as "normal".

**Suggested collection layers:**

| Layer | Technology | Nano types covered |
|---|---|---|
| Process/network events | eBPF (tracepoint: `sched_process_exec`, `sys_enter_*`; kprobe: `tcp_connect`) | `EBPF-*` |
| Syscall auditing | auditd (`-a always,exit -F arch=b64 -S ptrace,init_module,setns,bpf`) | `AUDIT` |
| File integrity | fanotify (`FAN_MODIFY|FAN_CREATE`) — inotify is not recursive and is expensive on large trees | `FIM` |
| Periodic snapshot | `/proc` scan (30–60 s) | `PROCSCAN` |
| Inventory delta | SUID/capability/package scan (1–6 h) | `INVENTORY` |

**Version differences summary:**

| Topic | 20.04 | 22.04 | 24.04 |
|---|---|---|---|
| SSH activation | `ssh.service` | `ssh.service` | **`ssh.socket`** |
| `sshd_config.d/` include | no | **yes** | yes |
| PHP-FPM unit | `php7.4-fpm` | `php8.1-fpm` | `php8.3-fpm` |
| AppArmor userns restriction | no | no | **yes** (`apparmor_restrict_unprivileged_userns=1`) |
| `snap-confine` path | `/usr/lib/snapd/` | `/usr/lib/snapd/` | `/usr/libexec/snapd/` |
| Default cgroup | v2 (hybrid possible) | v2 | v2 |
| Ubuntu Pro apt hooks | optional | installed by default | installed by default |
| `nftables` vs `iptables` | iptables-nft | iptables-nft | nftables-leaning |

**General FP allowlist units** (use as anchors, not binary names):
`unattended-upgrades.service`, `apt-daily*.service`, `snapd.service`,
`snapd.seeded.service`, `cloud-init*.service`, `logrotate.service`,
`man-db.service`, `plocate-updatedb.service`, `needrestart`, `dkms.service`,
`fwupd*.service`, `ua-timer.service`, `landscape-client.service`,
`packagekit.service`, `motd-news.service`.

---

## 9. Suggested Next Steps

1. Add `severity` (0–100) and `decay` (score fade time) to every nano; make the
   chain score a saturating function rather than a plain sum.
2. Move `INVENTORY`-type nanos into a separate "drift" engine — they are
   comparative rather than real-time and should raise a distinct alert class.
3. Map nano IDs 1:N to MITRE techniques and generate a machine-readable
   `mapping.yaml`; the ATT&CK Navigator layer then falls out automatically.
4. Write at least one **positive test** (Atomic Red Team style) and one
   **negative test** (known FP scenario) per nano, and run them in CI against the
   golden image.