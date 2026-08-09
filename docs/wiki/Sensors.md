# Sensors

The realtime sensor feeds syscall-shaped events into nano routers **in addition to** the periodic scan loop. GhostCatcher picks the best available backend at startup via `sensor.Auto()`.

Emitted findings label `src` honestly: live auditd-backed events use `AUDIT`; `/proc` polls use `PROCSCAN`; eBPF becomes `EBPF-*` when decode is real (today the eBPF path may still be a stub — see Build Tags).

## Backend selection order

```text
sensor.Auto()
   |
   v
+-----------------------------+
| 1. eBPF (with_ebpf build)   |  --- if attach succeeds, use this and stop.
+-----------------------------+
   |
   v
+-----------------------------+
| 2. auditd tail              |  --- if /var/log/audit/audit.log readable.
+-----------------------------+
   |
   v
+-----------------------------+
| 3. /proc poll               |  --- last-resort fallback (exec-only).
+-----------------------------+
```

## eBPF backend (`with_ebpf`)

- Implementation: [`internal/sensor/ebpf_linux.go`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/internal/sensor/ebpf_linux.go).
- Intended kinds: exec, openat, connect, ptrace, init_module, memfd, listen, socket, splice.
- Requires Linux ≥ 5.8, BPF capabilities, `-tags with_ebpf`.
- Until ringbuf decode is complete, prefer auditd for production live fidelity; nanos still route through the same `sensor.Event` shape.

## auditd backend

- Implementation: [`internal/sensor/auditd.go`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/internal/sensor/auditd.go).
- Tails `/var/log/audit/audit.log` (no libaudit).
- Parses `type=SYSCALL` for execve/execveat, openat, connect, ptrace, init_module/finit_module, memfd_create, listen, socket, splice.
- Joins **PATH/CWD/name/exe** fields onto the event (`Path`, `Extra["path"]`, `Extra["cwd"]`) so M5 credential and M1 docroot nanos can see file paths.
- Connect may decode AF_INET hex `addr=` into `RemoteIP` (IMDS detection).

Minimal `/etc/audit/rules.d/ghostcatcher.rules`:

```
-a always,exit -F arch=b64 -S execve,execveat       -k gc_exec
-a always,exit -F arch=b64 -S openat                -k gc_open
-a always,exit -F arch=b64 -S connect               -k gc_net
-a always,exit -F arch=b64 -S ptrace                -k gc_ptrace
-a always,exit -F arch=b64 -S init_module,finit_module -k gc_kmod
-a always,exit -F arch=b64 -S memfd_create          -k gc_memfd
-a always,exit -F arch=b64 -S listen,socket,splice  -k gc_sock
```

Reload with `augenrules --load`.

## /proc poll backend

- Implementation: [`internal/sensor/procpoll.go`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/internal/sensor/procpoll.go).
- Emits synthetic **exec** events for new PIDs only.
- Cannot see openat/connect/ptrace/memfd; periodic scanners cover at-rest state.

## Live nano routing

`runner.consumeSensor` treats these kinds as fast-path:

| Kind | Routers (examples) |
|------|--------------------|
| `exec` | sudden-root seed; `defense.RouteExec` (GTFOBins, AppArmor, firewall, snap, journal, tmpfs); `containeresc.RouteExec` |
| `openat` | `credential.RouteOpenat`; `containeresc.RouteFile`; `web.RouteDocrootWrite` |
| `connect` | `NETWORK_IMDS_ACCESS` when remote is link-local metadata |
| `ptrace` | `PROC_PTRACE_INJECT`; optional cross-UID mem read |
| `memfd_create` | `PROC_MEMFD_EXEC` |
| `init_module` | `KERNEL_MODULE_LOAD` |
| `socket` | copyfail AF_ALG (CVE-2026-31431) |

Additionally, when `sudden_root.enabled` is true, a ~1s `/proc` credential snapshot loop emits `PROC_SUDDEN_ROOT`.

## FIM and inventory (not the live sensor)

| Source | Mechanism | Typical nanos |
|--------|-----------|---------------|
| **FIM** | fsnotify → debounced `RunOnce` + hash deltas in persistence/fimextra/web | SSH drop-ins, cron, apt hooks, motd, profile, log truncate |
| **INVENTORY** | Periodic dpkg verify / SUID / caps / web baseline | `LIB_HASH_MISMATCH`, `SUID_*`, `WEB_APP_FILE_TAMPER` |
| **PROCSCAN** | Periodic `/proc` maps, net, ancestry, worker children | `PROC_RWX_*`, `PROC_SOCKET_STDIO`, `WEB_WORKER_*` |

Sensitive path coverage (Ubuntu M2.4 surfaces included) is listed in [`internal/watch/sensitive.go`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/internal/watch/sensitive.go).

## What the sensor cannot see

- Pure userland reflection with no syscall (compensate with YARA memory / maps).
- Other user namespaces if the agent is not in the host PID namespace.
- Encrypted payload contents — sockets are classified, not decrypted.

## Cross-references

- **[Behavior Taxonomy](Behavior-Taxonomy)** — how `src` maps to nanos.
- **[Architecture](Architecture)** — pipeline placement.
- **[Build Tags](Build-Tags)** — `with_ebpf`.
