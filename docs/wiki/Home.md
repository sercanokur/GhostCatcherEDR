# GhostCatcher Wiki

GhostCatcher is an open-source Linux endpoint detection agent written in Go. It runs as a single binary or as a `systemd` service, watches the host for the behaviors APT operators rely on most on Linux (web shells, preload-based hijacks, SSH/cron/systemd persistence, PAM/sudoers tampering, SUID drift, reverse shells, reflective loads), and ships line-delimited JSON events to your SIEM.

This wiki is the long-form documentation. The repository [`README.md`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/README.md) contains the quick reference; the wiki goes deeper.

## What you can do here

- Get a working agent up and running — see **[Getting Started](Getting-Started)**.
- Understand the moving parts and build tags — see **[Architecture](Architecture)** and **[Build Tags](Build-Tags)**.
- Tune detection behavior to your environment — see **[Detections](Detections)**, **[Rule Pack](Rule-Pack)**, **[Sensors](Sensors)**.
- Wire events into your SIEM — see **[Sinks and SIEM](Sinks-and-SIEM)**.
- Operate it day to day — see **[Baselines and Learning Mode](Baselines-and-Learning-Mode)**, **[Operations Runbook](Operations-Runbook)**, **[Quarantine and Self Guard](Quarantine-and-Self-Guard)**.
- Keep detection quality from regressing — see **[Evaluation Harness](Evaluation-Harness)**.

## Design principles

1. **Open and inspectable.** Every detector, expression, and threshold is in the repo. There is no managed cloud control plane.
2. **Host-visible only.** The agent watches `/proc`, `/etc`, web roots, syscalls via eBPF/auditd, and process ancestry. It does not require a kernel module or TLS interception.
3. **Multi-signal.** Single signals rarely fire alerts on their own; rules combine pattern, entropy, ownership, ancestry, network, and IOC matches before crossing the alert threshold.
4. **Quiet by default.** Learning mode + per-rule rate limits + dedup keep the noise floor low; alerts are meant to be actionable, not exhaustive.
5. **Fail closed where it matters.** Signed rule packs, agent self-guard, baseline-commit 2FA, and an on-disk spool exist so that compromise of the underlying host is harder to hide.

## Compatibility matrix

| Layer | Supported |
|-------|-----------|
| OS | Linux (Debian/Ubuntu, RHEL/CentOS/Fedora, Amazon Linux, openSUSE). macOS only for development/testing. |
| Architecture | amd64, arm64. |
| Kernel for eBPF | Linux ≥ 5.8 with `CONFIG_BPF_SYSCALL=y` (`-tags with_ebpf`). Older kernels fall back to auditd then `/proc` polling. |
| YARA | Optional. Requires libyara ≥ 4.3 and a cgo build (`-tags with_yara`). |
| Container runtimes detected | Docker, containerd, cri-o, Kubernetes, LXC. |
| SIEMs | UDP/TCP/TLS syslog, Splunk HEC, Elasticsearch `_bulk`, Grafana Loki. |

## At a glance

```text
                +----------------+
                |    sensors     |  eBPF | auditd | proc-poll
                +-------+--------+
                        v
+------+      +---------+---------+      +----------+
| /proc| ---> |  detection passes | ---> |  rules   |  expr eval + correlation
+------+      +---------+---------+      +----+-----+
                        v                     v
                +-------+----------+    +-----+-------+
                |  enrichment      |    | rate-limit  |
                |  (IOC, container)|    | + dedup     |
                +-------+----------+    +-----+-------+
                        v                     v
                +-------+---------------------+----+
                |          sinks              |    |  stdout JSONL
                |  syslog/HEC/_bulk/Loki      | +-->  /var/spool/.../events.ndjson
                +-----------------------------+----+
```

Continue with **[Getting Started](Getting-Started)** to install and run your first scan.
