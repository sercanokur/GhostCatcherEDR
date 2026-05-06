# Troubleshooting

Common failure modes, what they look like, and how to fix them. Each entry follows the same pattern: **symptom → diagnose → fix**.

## Startup

### `require_root set but not running as root`

- **Symptom:** `ghostcatcher run` exits with this message and code 1.
- **Diagnose:** `id`. The agent was launched without `sudo` or by a user other than UID 0.
- **Fix:** run as root, or set `require_root: false` if you understand the reduced visibility.

### `rule pack signature verification failed`

- **Symptom:** Agent refuses to start.
- **Diagnose:**

  ```bash
  openssl pkeyutl -verify -pubin -inkey /etc/ghostcatcher/rulepack.pub \
    -in /etc/ghostcatcher/rule_pack.yaml \
    -sigfile /etc/ghostcatcher/rule_pack.yaml.sig
  ```

  Compare the public key hash on the host to the build host.
- **Fix:** re-sign the pack with the matching key, or stage the new public key on the host before pushing the new signature.

### `rule pack invalid` / `compile: unexpected token`

- **Symptom:** `check-config` exits non-zero.
- **Diagnose:** the failing rule's `expr` is malformed. The error includes the offending token. Common culprits: unquoted strings, missing parens around `or` expressions, using `matches` without a regex argument.
- **Fix:** see the grammar in **[Rule Pack](Rule-Pack)** and unit-test the expression with the snippet:

  ```bash
  go test ./internal/rules -run TestExpr
  ```

### `config invalid: baseline_path not writable`

- **Symptom:** `check-config` fails.
- **Diagnose:** `ls -ld /var/lib/ghostcatcher`. Path missing or owned by another user.
- **Fix:** `sudo install -d -m 0700 -o root -g root /var/lib/ghostcatcher`.

## Sensor

### Sensor selected `proc` instead of `ebpf`

- **Symptom:** Startup log shows `sensor backend selected backend=proc` despite a `with_ebpf` build.
- **Diagnose:**

  ```bash
  uname -r              # 5.8+ ?
  ls /sys/kernel/btf/vmlinux  # CO-RE BTF available?
  capsh --print | grep cap_bpf
  ```

- **Fix:** ensure the kernel + capabilities are present; pin `sensor.backend: ebpf` to fail closed if you require it.

### eBPF ringbuffer overruns

- **Symptom:** Periodic `ringbuffer.overrun` warnings; sporadic missed events.
- **Diagnose:** host is very busy (high syscall rate from a noisy workload).
- **Fix:** raise `sensor.debounce_ms`, restrict `ancestry_juicy_parents` / `ancestry_child_set`, or fall back to auditd which has its own rate limits configured at the kernel level.

### auditd backend sees nothing

- **Symptom:** `backend=audit` selected but no exec/openat events ever appear.
- **Diagnose:**

  ```bash
  sudo ausearch -k gc_exec | head
  sudo systemctl status auditd
  ```

- **Fix:** install the rules from **[Sensors → auditd backend](Sensors)** and `augenrules --load`.

## Detection noise

### Burst of `WEB_FILE_NEW` after a deploy

- **Symptom:** thousands of `WEB_FILE_NEW` events the moment a new release goes out.
- **Diagnose:** the deploy created or replaced files under `document_roots` that are not in the baseline.
- **Fix:** rotate the baseline as part of the deploy pipeline (see **[Operations Runbook](Operations-Runbook)** → "Rotating the baseline"). Add CI/CD-generated cache prefixes to `path_allowlist_prefixes`.

### `MAPS_RWX` constantly firing for a JIT (Java, .NET, V8)

- **Symptom:** repeated alerts on an interpreter that legitimately allocates RWX.
- **Diagnose:** check `evidence.path` of the offending event.
- **Fix:** add the path prefix to `maps_path_allowlist_prefixes`. If the JIT only writes-then-execs (W^X), narrow `maps_watch_processes` to exclude its `comm`.

### `PROC_RARE_ANCESTRY` fires for a known cron job

- **Symptom:** A scheduled administrative script trips the rare-ancestry rule every run.
- **Diagnose:** the parent/child pair was not present at the last `baseline commit`.
- **Fix:** rerun `baseline commit` (planned change), or extend `ancestry_child_set` to exclude the binary, or switch the cron job to use `bash -lc` so the parent comm becomes consistent with what was baselined.

### Web shell false positive on framework cache

- **Symptom:** `WEB_SHELL_PATTERN` on `storage/framework/views/abcd.php`.
- **Diagnose:** Laravel/Twig generated PHP. The taint signal is absent; only the regex matched.
- **Fix:** add `storage/framework/views/` to `path_allowlist_prefixes`. Do **not** lower the rule weight — that would help one host while hurting every other.

## Sinks

### Spool grows without bound

- **Symptom:** `/var/spool/ghostcatcher/events.ndjson` keeps growing; sink alerts missing in SIEM.
- **Diagnose:**

  ```bash
  journalctl -u ghostcatcher | grep sink
  ```

  Look for the failing sink and the underlying error (TLS, 401, refused, timeout).
- **Fix:** correct the credential / firewall issue. The spool drains automatically on next success; force-drain by restarting the agent.

### Splunk HEC returns 401

- **Symptom:** repeating `splunk: status 401` in the journal.
- **Diagnose:** token revoked or wrong index.
- **Fix:** rotate the token, update `splunk_hec.token`, restart.

### Truncated UDP syslog

- **Symptom:** `MSG` field is cut off; JSON parser fails on the SIEM side.
- **Diagnose:** event byte length > `max_msg_bytes` or > network MTU.
- **Fix:** raise `max_msg_bytes`, then move to TCP/TLS syslog. UDP is best-effort and capped by MTU; large `evidence` blocks (e.g. PHP shell snippets) blow the budget.

## Self-guard

### `AGENT_TAMPERED` after package update

- **Symptom:** A planned upgrade was followed by `AGENT_TAMPERED` alerts.
- **Diagnose:**

  ```bash
  sha256sum /usr/local/bin/ghostcatcher
  grep expected_sha256 /etc/ghostcatcher/config.yaml
  ```

- **Fix:** rotate `selfguard.expected_sha256` as part of the upgrade (see **[Operations Runbook](Operations-Runbook)**).

### Watchdog restarts not happening on tamper

- **Symptom:** `AGENT_TAMPERED` event fires once, then nothing. The agent keeps running with the bad binary.
- **Diagnose:** `systemctl show ghostcatcher.service | grep -E 'Type=|WatchdogSec='`. Either `Type` is not `notify` or `WatchdogSec` is unset.
- **Fix:** edit the unit to `Type=notify` + `WatchdogSec=30`, `daemon-reload`, restart.

## Baseline

### `baseline commit` says nothing changed but you expected it to

- **Symptom:** `baseline committed path=...` log; the next scan still alerts on the same files.
- **Diagnose:** the commit ran with a different config (e.g. the wrong `document_roots`). `cat /etc/ghostcatcher/config.yaml` matches what the service uses?
- **Fix:** re-run `ghostcatcher baseline commit -config /etc/ghostcatcher/config.yaml` with the same path that the systemd unit uses.

### `2fa required but env var is empty`

- **Symptom:** `baseline commit` exits non-zero with this message.
- **Diagnose:** `baseline_commit_token_env` is set; the env var is missing in the shell that ran the command.
- **Fix:** export the var (typically from your secret manager) and use `sudo -E` so it crosses the privilege boundary.

## Rule pack expressions

### A rule that should fire never does

- **Symptom:** the underlying signal is in `signals[]` but `rule_id` never appears.
- **Diagnose:** the rule's `expr` evaluates to false. Test it:

  ```bash
  go test ./internal/rules -run TestExpr_Eval -v
  ```

  Or temporarily set the rule's `expr: "true"` and re-run the harness.
- **Fix:** correct the expression. Common pitfalls:
  - using `=` instead of `==`,
  - comparing string and int,
  - omitting parens around an `or` expression that needs to be the whole condition,
  - referencing a field name that does not exist (treated as `null`, which is falsy).

### A rule fires too aggressively

- **Symptom:** every event from a detector emits the rule.
- **Diagnose:** `min_signals` or the `expr` is too loose.
- **Fix:** raise `min_signals`, tighten the expression with `confidence >= N`, or add a correlation requirement (`correlate: [...]`).

## Build

### `cgo: cannot find -lyara`

- **Symptom:** `with_yara` build fails to link.
- **Fix:** install `libyara-dev` (Debian/Ubuntu) or `yara-devel` (RHEL/CentOS/Fedora). Make sure `pkg-config --libs yara` returns sensible flags.

### `with_ebpf` build fails on macOS

- **Symptom:** "no such file or directory: linux/bpf.h".
- **Fix:** the eBPF backend is Linux-only. Either drop the tag for macOS development or cross-compile with `GOOS=linux GOARCH=amd64 go build -tags with_ebpf`.

## When all else fails

Set `agent_log_level: debug` and tail the journal:

```bash
journalctl -u ghostcatcher -f -o cat
```

Most subsystems emit a debug line per scan pass with timing and counts; that is usually enough to narrow the issue to a specific detector or sink. If the issue persists, file an issue on the repo with:

- `ghostcatcher --version` output (or first stderr line if the binary is older),
- the relevant journal slice with `agent_log_level: debug`,
- a sanitized config (`ghostcatcher check-config -config <path>` output),
- corpus samples that reproduce the false positive / negative if any.
