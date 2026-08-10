GhostCatcher host-cost profiles
================================

Ready-to-copy YAML templates that trade detection latency for host load.
Start from balanced.yaml unless you know you need something else.

  light.yaml       — low-traffic / constrained hosts
  balanced.yaml    — default production stance (matches config.Default)
  heavy-host.yaml  — large docroots / dense process tables (15m full scan)
  lab.yaml         — demo / evaluation harness (aggressive cadence)

Install
-------
1. Copy a profile to /etc/ghostcatcher/config.yaml
2. Set document_roots, watched_units, and sink blocks for the host
3. Point rule_pack_path / mapping_path at the installed pack
4. ghostcatcher check-config -config /etc/ghostcatcher/config.yaml

Repo paths in these files point at configs/rule_pack.example.yaml so
`check-config` works from a git checkout. Rewrite them for production.

Load notes (lab / heavy)
------------------------
- Prefer sensor.backend: auto (or auditd) so live nanos stay cheap while
  scan_interval is long.
- Do not copy lab.yaml knobs (1m scan, integrity 5m, sudden_root 1s) to prod.
- Busy-docroot local check: go test -bench=BenchmarkWebScan_Busy ./internal/detect/web/
