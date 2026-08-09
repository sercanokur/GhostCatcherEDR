# GhostCatcher Wiki

GhostCatcher is an open-source Linux endpoint detection agent written in Go. It runs as a single binary or as a `systemd` service, watches the host for Ubuntu-focused attacker behaviors (web RCE, admin persistence, privesc, defense weakening, concealment, credential theft, container escape), and ships **schema 1.3** JSONL events to your SIEM.

This wiki is the long-form documentation. The repository [`README.md`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/README.md) is the quick reference; the behavior tree lives in [`bhv.md`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/bhv.md).

## What you can do here

- Get a working agent up and running — **[Getting Started](Getting-Started)**.
- Understand Macro→Micro→Nano and CHAIN-1…6 — **[Behavior Taxonomy](Behavior-Taxonomy)**.
- See the pipeline and packages — **[Architecture](Architecture)** and **[Build Tags](Build-Tags)**.
- Tune detections — **[Detections](Detections)**, **[Rule Pack](Rule-Pack)**, **[Sensors](Sensors)**.
- Wire events into your SIEM — **[Sinks and SIEM](Sinks-and-SIEM)**.
- Operate day to day — **[Baselines and Learning Mode](Baselines-and-Learning-Mode)**, **[Operations Runbook](Operations-Runbook)**, **[Quarantine and Self Guard](Quarantine-and-Self-Guard)**.
- Keep quality from regressing — **[Evaluation Harness](Evaluation-Harness)**.

## Design principles

1. **Open and inspectable.** Every detector, expression, and threshold is in the repo. There is no managed cloud control plane.
2. **Host-visible only.** The agent watches `/proc`, `/etc`, web roots, syscalls via eBPF/auditd, and process ancestry. It does not require a kernel module or TLS interception.
3. **Behavior-tree first.** Detections are nanos under six macros; process names are never the primary **anchor** (prefer cgroup / systemd unit).
4. **Multi-signal + chains.** Standalone nanos score individually; ordered CHAIN-1…6 correlations raise confidence when the same anchor advances through an attack story.
5. **Quiet by default.** Learning mode, per-rule rate limits, dedup, and `fp_allowlist_units` keep the noise floor low.
6. **Fail closed where it matters.** Signed rule packs, agent self-guard, baseline-commit 2FA, and an on-disk spool exist so host compromise is harder to hide.

## Compatibility matrix

| Layer | Supported |
|-------|-----------|
| OS | Linux (Debian/Ubuntu primary for bhv.md coverage; RHEL/CentOS/Fedora, Amazon Linux, openSUSE also run). macOS only for development/testing. |
| Architecture | amd64, arm64. |
| Kernel for eBPF | Linux ≥ 5.8 with `CONFIG_BPF_SYSCALL=y` (`-tags with_ebpf`). Older kernels fall back to auditd then `/proc` polling. |
| YARA | Optional. Requires libyara ≥ 4.3 and a cgo build (`-tags with_yara`). |
| Container runtimes detected | Docker, containerd, cri-o, Kubernetes, LXC/LXD. |
| SIEMs | UDP/TCP/TLS syslog, Splunk HEC, Elasticsearch `_bulk`, Grafana Loki. |
| Event schema | **1.3** (`macro`, `micro`, `src`, `type`, `anchor`, `conf_band`, `chain_id`, `evidence_loss`) |

## At a glance

```text
  sensors (eBPF | AUDIT | PROCSCAN)     FIM (fsnotify)     INVENTORY (dpkg/SUID)
              \                              |                      /
               +--------------> detectors by Macro M1–M6 <---------+
                                      |
                         taxonomy.Apply (mapping.yaml)
                                      |
                    pairwise correlate + CHAIN-1…6 (same anchor)
                                      |
                         OODA Orient → Decide → Act
                                      |
                    sinks: stdout JSONL | syslog | HEC | Elastic | Loki
                                      +--> spool / quarantine / self-guard
```

Continue with **[Getting Started](Getting-Started)** or **[Behavior Taxonomy](Behavior-Taxonomy)**.
