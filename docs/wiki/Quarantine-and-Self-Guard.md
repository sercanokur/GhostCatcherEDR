# Quarantine and Self Guard

These two subsystems harden the agent against the realities of working on a host that may already be partly compromised: the **quarantine** vault keeps copies of file-based evidence even if the originals are wiped, and **selfguard** detects tampering with the agent binary itself.

## Quarantine

When a file-based event is emitted with `confidence ≥ quarantine_min_confidence`, the runner:

1. Computes the SHA-256 of the original file (in addition to whatever hash the detector already produced).
2. Copies the file into `<quarantine_dir>/<YYYYMMDD>/<sha256>.bin`, `mode 0400`, owned by root.
3. Writes a sibling JSON sidecar `<sha256>.json` containing the originating event and the original file's metadata (mode, owner, mtime, link count, xattrs).
4. Emits a `QUARANTINE_STORED` informational event linking the original detection's `dedup_key` to the vault path.

Implementation: [`internal/quarantine/quarantine.go`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/internal/quarantine/quarantine.go).

### Layout

```
/var/lib/ghostcatcher/quarantine/
├── 20260424/
│   ├── 5e8c0f...c2.bin
│   ├── 5e8c0f...c2.json
│   ├── 9b2a11...e0.bin
│   └── 9b2a11...e0.json
├── 20260425/
│   └── ...
└── _meta/
    └── manifest.ndjson    # append-only ledger of every store
```

Each sidecar looks like:

```json
{
  "stored_at": "2026-04-24T19:21:33.022Z",
  "sha256": "5e8c0f...c2",
  "size": 2148,
  "original_path": "/var/www/html/.cache.php",
  "original_mode": "0644",
  "original_owner": "www-data",
  "original_mtime": "2026-04-24T19:20:51Z",
  "rule_id": "WEB_SHELL_PATTERN",
  "technique_id": "T1505.003",
  "confidence": 92,
  "signals": ["WEB_SHELL_PATTERN","WEB_TAINT_FLOW","ENTROPY_HIGH"],
  "evidence": { "...": "..." }
}
```

`_meta/manifest.ndjson` appends one line per store and is the easiest place to grep when you are investigating after the fact.

### Configuration

```yaml
quarantine_dir: /var/lib/ghostcatcher/quarantine
quarantine_min_confidence: 85
quarantine_max_bytes_per_artifact: 33554432   # 32 MiB
```

If `quarantine_dir` is empty, the subsystem is disabled and the runner only emits the original detection.

### Permissions

- The vault root is `0700` and owned by root. The agent never makes the vault world-readable.
- Each artifact is `0400`. Refuse to make it executable so it cannot be re-run accidentally.
- Mount the vault on a partition with `nodev,nosuid,noexec` for an additional layer.
- Back up the vault on the same schedule as your incident-response evidence (daily snapshot, off-host copy).

### Restoring or analysing

Artifacts are byte-exact copies. To examine without contaminating timelines:

```bash
sudo install -m 0400 -o root -g root \
  /var/lib/ghostcatcher/quarantine/20260424/5e8c0f...c2.bin \
  /tmp/sample.bin

file /tmp/sample.bin
sha256sum /tmp/sample.bin
strings -n 8 /tmp/sample.bin | head -50
```

Pair with the sidecar to reconstruct the original mode / owner / mtime if you need to mount it inside a sandbox.

### What is **not** quarantined

- Network-only events (no file to copy).
- Kernel module load events — the on-disk module file is what gets copied, but live module memory is left alone.
- Process memory regions detected by `/proc/maps` heuristics. Use the YARA memory scanner if you need a memory dump.

## Self Guard

The agent binary is the most attractive target on the host: silently replace it with a no-op and the entire detection layer goes dark. `selfguard` makes that loud.

Implementation: [`internal/selfguard/selfguard.go`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/internal/selfguard/selfguard.go).

### What it does

1. At startup, reads `selfguard.binary_path` (the absolute path to the running binary, typically `/usr/local/bin/ghostcatcher`).
2. Computes the SHA-256.
3. If `selfguard.expected_sha256` is set and matches → start the watchdog loop.
4. If `expected_sha256` is empty → log the computed value at `info` and start the watchdog loop using the runtime hash as a soft baseline (it will detect changes that happen *while* the agent runs, but cannot detect a swap before startup).
5. Every `selfguard.check_interval` (default `5m`):
   - Re-hash the binary.
   - On mismatch, emit `AGENT_TAMPERED` (severity `critical`, technique `T1562.001`) to every sink and **stop pinging the systemd watchdog**.
6. Throughout, if `NOTIFY_SOCKET` is set (i.e. running under `Type=notify`), send `WATCHDOG=1` at half the interval defined in `WATCHDOG_USEC` from the unit.

### Configuration

```yaml
selfguard:
  binary_path: /usr/local/bin/ghostcatcher
  expected_sha256: "8f7a..."     # produced by `sha256sum`
  check_interval: 5m
  systemd_watchdog: true
```

To bake the hash into the unit at install time:

```bash
SHA="$(sha256sum /usr/local/bin/ghostcatcher | awk '{print $1}')"
sudo sed -i "s/__GC_SHA__/$SHA/" /etc/ghostcatcher/config.yaml
```

### Pairing with systemd

```ini
# /etc/systemd/system/ghostcatcher.service
[Service]
Type=notify
WatchdogSec=30
Restart=on-failure
ExecStart=/usr/local/bin/ghostcatcher run -config /etc/ghostcatcher/config.yaml
```

With `selfguard.check_interval: 5m` and `WatchdogSec=30`, the agent pings every 15 s. A tampered binary stops pinging within 30 s, systemd kills the unit, and `Restart=on-failure` brings up the (now mismatched) binary, which immediately emits `AGENT_TAMPERED` again. The cycle is a loud alert on your SIEM.

If you do not run under systemd, the `AGENT_TAMPERED` event is still produced; the watchdog loop just becomes a no-op.

### Why not also self-update?

Self-update is intentionally not implemented. Update GhostCatcher through whatever you already trust (apt, rpm, immutable image, configuration management). Letting a host update its own EDR binary creates a path for an attacker to upgrade themselves into invisibility.

### Limitations

- **Pre-startup swap.** If `expected_sha256` is empty and the binary is replaced before the agent starts, the runtime hash becomes the soft baseline. Pin the expected hash in production.
- **Library substitution.** `selfguard` hashes the binary, not its dynamic libraries. For static linking use `CGO_ENABLED=0` (the default build); if you ship a cgo build (`with_yara`), pin libyara via your package manager and run `dpkg --verify` / `rpm -V` against it via the integrity scanner.
- **In-memory patching.** A privileged attacker can `ptrace` the running process and patch instructions in memory. The `MAPS_RWX` and `PROC_TRACED` rules cover that case; selfguard alone cannot.

## Cross-references

- **[Detections](Detections)** for `AGENT_TAMPERED`, `MAPS_RWX`, `PROC_TRACED`, the file-based rules that drive quarantine.
- **[Operations Runbook](Operations-Runbook)** for restart, hash-rotation, and quarantine-archive procedures.
- **[Configuration](Configuration)** for the YAML keys.
