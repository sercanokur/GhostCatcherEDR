# Build Tags

GhostCatcher ships as a single Go binary. Two optional capabilities — **YARA** scanning and the **eBPF** sensor — depend on build tags so the default build remains a pure-Go static binary that runs anywhere with no native dependencies.

## Default build

```bash
go build -o ghostcatcher ./cmd/agent
```

- Pure Go, `CGO_ENABLED=0` by default.
- Runs on Linux (full feature set minus YARA/eBPF) and on macOS for development/testing.
- Sensor backend will choose **auditd** or **/proc poll**; eBPF is a no-op stub.
- YARA is a no-op stub that always returns "no match".

This is the build you should ship to most production hosts unless you have a specific reason to enable the optional capabilities.

## `with_yara`

Enables YARA-based disk and memory scanning via [`hillu/go-yara/v4`](https://github.com/hillu/go-yara).

```bash
CGO_ENABLED=1 go build -tags with_yara -o ghostcatcher ./cmd/agent
```

### Requirements

- libyara ≥ 4.3 with development headers.
- A C compiler (gcc or clang).
- `pkg-config` (used by `go-yara` to find libyara).

Install on Debian/Ubuntu:

```bash
sudo apt-get install -y libyara-dev pkg-config build-essential
```

Install on RHEL/CentOS/Fedora:

```bash
sudo dnf install -y yara-devel pkgconf-pkg-config gcc
```

### What changes

| File | Tag | Behavior |
|------|-----|----------|
| `internal/detect/yara/yara_stub.go` | `!with_yara` | `Scan()` returns no events. |
| `internal/detect/yara/yara_cgo.go` | `with_yara` | Compiles rules from `yara_rules_dir`, scans configured paths and (if `yara_memory_enabled`) live process memory. |

Configuration becomes meaningful (see **[Configuration](Configuration)** for the full set):

```yaml
yara_rules_dir: /etc/ghostcatcher/yara
yara_memory_enabled: true
yara_memory_processes:
  - nginx
  - php-fpm
  - apache2
```

### Cost and caveats

- Memory scanning is expensive on processes with large RSS. Restrict `yara_memory_processes` to the comms you actually care about.
- libyara has its own CVE history; track it via `govulncheck` and your distro's security advisories. The integrity scanner will catch unexpected changes to `libyara.so` if you have it in `integrity_paths`.
- Static linking libyara is possible but requires a custom build of libyara with `--enable-static`. Most users use a dynamically linked agent.

## `with_ebpf`

Enables the eBPF realtime sensor via [`cilium/ebpf`](https://github.com/cilium/ebpf).

```bash
go build -tags with_ebpf -o ghostcatcher ./cmd/agent
```

### Requirements

- Linux kernel ≥ 5.8 with `CONFIG_BPF_SYSCALL=y`. `CONFIG_DEBUG_INFO_BTF=y` is recommended for CO-RE.
- The runtime must have `CAP_BPF` and `CAP_PERFMON` (or be root).
- `cilium/ebpf` is pure Go — **no cgo required** for this tag. You can combine it with the default build:

  ```bash
  go build -tags with_ebpf -o ghostcatcher ./cmd/agent
  ```

### What changes

| File | Tag | Behavior |
|------|-----|----------|
| `internal/sensor/ebpf_stub.go` | `!with_ebpf` | eBPF backend is unavailable; auto-selection skips it. |
| `internal/sensor/ebpf_linux.go` | `with_ebpf && linux` | Attaches tracepoints for exec/openat/connect/ptrace/init_module/memfd_create. |

When eBPF is enabled and `sensor.backend: auto`, the agent will prefer it on every Linux startup. To force the choice in production:

```yaml
sensor:
  backend: ebpf      # fail-closed if eBPF cannot start
```

### Cost and caveats

- A single per-CPU ringbuffer; on extremely busy hosts you may see overruns. The agent logs them and continues; the periodic scan still picks up missed state.
- Some kernels behind unusual security modules (LKRG, certain hardened distros) refuse `bpf()` even with capability. The agent falls back to auditd in that case (or fails fast if `sensor.backend: ebpf` is pinned).

## Combining

```bash
CGO_ENABLED=1 go build -tags "with_yara with_ebpf" -o ghostcatcher ./cmd/agent
```

Both tags are independent; they touch different packages and never share state.

## CI matrix

The shipped CI builds three variants and runs the test suite for each:

| Job | Tags | Purpose |
|-----|------|---------|
| `default` | none | Sanity that the pure-Go build works on linux/amd64 and linux/arm64. |
| `ebpf` | `with_ebpf` | Compiles the eBPF backend. (Tests are gated to environments with `CAP_BPF`.) |
| `yara` | `with_yara` | Compiles the YARA backend with libyara installed. |

Add a fourth `release` job that builds with `with_yara with_ebpf` for tag pushes if you ship hardened binaries.

## Identifying which build is running

The `agent_version` field of every event includes a build suffix derived from `runtime/debug.BuildInfo` settings. To inspect at runtime:

```bash
ghostcatcher run -config /dev/null -once 2>&1 | head -1
```

The first stderr line includes `build_tags=...`. Use it to confirm the production binary has the tags you expected.
