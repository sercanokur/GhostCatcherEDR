# Sensors

The realtime sensor is the agent's nervous system. It feeds exec, openat, connect, ptrace, init_module and memfd events into the engine in addition to the periodic scan loop. GhostCatcher does not commit to one backend — it picks the best available at startup using `sensor.Auto()`.

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
| 2. auditd tail              |  --- if /var/log/audit/audit.log readable, use it.
+-----------------------------+
   |
   v
+-----------------------------+
| 3. /proc poll               |  --- last-resort fallback.
+-----------------------------+
```

The choice is logged at startup:

```
INFO sensor backend selected backend=ebpf
```

## eBPF backend (`with_ebpf`)

- Implementation: [`internal/sensor/ebpf_linux.go`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/internal/sensor/ebpf_linux.go) using `github.com/cilium/ebpf`.
- Attaches tracepoints for:
  - `sched/sched_process_exec`
  - `syscalls/sys_enter_openat`
  - `syscalls/sys_enter_connect`
  - `syscalls/sys_enter_ptrace`
  - `syscalls/sys_enter_init_module`
  - `syscalls/sys_enter_memfd_create`
- Requires:
  - Linux kernel ≥ 5.8 with `CONFIG_BPF_SYSCALL=y`, `CONFIG_DEBUG_INFO_BTF=y` for CO-RE.
  - `CAP_BPF` and `CAP_PERFMON` (or root).
  - The binary built with `-tags with_ebpf`.
- Produces lightweight `Event{Comm, Pid, Ppid, Argv, FilePath, RemoteAddr}` records consumed by the runner. The full enrichment (cgroup, ancestors, ioc) happens later in the pipeline.

The eBPF code path is intentionally narrow: it keeps a per-CPU ringbuffer and never blocks. If the ringbuffer overruns, the agent logs a warning and continues; the periodic scan still catches what was missed.

## auditd backend

- Implementation: [`internal/sensor/auditd.go`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/internal/sensor/auditd.go).
- Tails `/var/log/audit/audit.log` (no libaudit dependency, no netlink socket — works behind read-only root filesystems and inside containers that mount the log read-only).
- Parses `type=SYSCALL` records for `execve`, `openat`, `connect`, `ptrace`, `init_module`, `finit_module`, `memfd_create` and emits the same `Event` shape as the eBPF backend.
- You should make sure `auditd` is actually configured to record the syscalls of interest. A minimal augment for `/etc/audit/rules.d/ghostcatcher.rules`:

  ```
  -a always,exit -F arch=b64 -S execve,execveat       -k gc_exec
  -a always,exit -F arch=b64 -S openat                -k gc_open
  -a always,exit -F arch=b64 -S connect               -k gc_net
  -a always,exit -F arch=b64 -S ptrace                -k gc_ptrace
  -a always,exit -F arch=b64 -S init_module,finit_module -k gc_kmod
  -a always,exit -F arch=b64 -S memfd_create          -k gc_memfd
  ```

  Reload with `augenrules --load`.

## /proc poll backend

- Implementation: [`internal/sensor/procpoll.go`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/internal/sensor/procpoll.go).
- Scans `/proc` every second for new PIDs, reads `comm`, `cmdline`, `ppid`, `cgroup`, and emits exec events for anything not seen on the previous tick.
- Cannot see openat / connect / ptrace / init_module / memfd events. It is a strict last resort, used so the agent stays useful on hosts with no eBPF and no auditd.
- Cost is low (`O(running_pids)` per second) but it will miss short-lived processes that exit between polls.

## Per-event flow

```text
sensor.Source.Events() ---> runner.consumeSensor goroutine
                              |
              +---------------+----------------+
              |                                |
   debounced rescan                emit ancestry / network
   (juicy syscalls only:           events directly
    ptrace, init_module,
    memfd_create, exec under
    a juicy parent)
```

## Tuning

- **Disable the sensor entirely.** Set `sensor.disabled: true` in YAML. The periodic scanner remains active.
- **Force a backend.** Set `sensor.backend: ebpf | audit | proc`. The agent fails closed if the requested backend cannot start (so production hosts do not silently fall back to a less capable backend).
- **Backoff on noisy hosts.** `sensor.debounce_ms` controls how aggressively the consumer collapses bursts before triggering a `RunOnce`.

## What the sensor cannot see

- Userland-only events that never cross a syscall boundary (e.g. a Java app loading a class via reflection from an in-memory jar). Use the YARA memory scan or `/proc/maps` to compensate.
- Events that occur in a separate user namespace where the agent has no view into `/proc`. Run the agent in the host PID/user namespace.
- Encrypted network payloads — GhostCatcher classifies sockets, not bytes. Use a dedicated network sensor for content inspection.

## Cross-references

- **[Architecture](Architecture)** for the overall data flow.
- **[Detections](Detections)** for the rules that consume sensor events.
- **[Build Tags](Build-Tags)** for how to enable `with_ebpf`.
