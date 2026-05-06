# Sinks and SIEM

Every detection event is JSON. The same JSON is delivered to **every** enabled sink and always to **stdout**. Sinks are independent: enabling Splunk does not disable syslog, and the failure of one sink does not affect the others.

When a sink fails (TCP refused, HTTP 5xx, TLS handshake error, etc.) the raw line is appended to the on-disk **spool** at `spool_dir`. On the next successful write to that sink, the spool is drained in order.

## Common payload

The payload is described under **[Detections → Output format](Detections)** and in [`internal/event/event.go`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/internal/event/event.go). Stable top-level fields:

```json
{
  "schema_version": "1.1",
  "agent_version": "0.2.0",
  "timestamp": "2026-04-24T19:21:33.018Z",
  "rule_id": "WEB_SHELL_PATTERN",
  "rule_pack_version": "2025.04.0",
  "technique_id": "T1505.003",
  "tactic": "persistence",
  "severity": "high",
  "confidence": 92,
  "correlation_id": "8b1f8c7c2e",
  "learning_only": false,
  "dedup_key": "WEB_SHELL_PATTERN:/var/www/html/.cache.php:sha256:5e..",
  "entity": { "type": "file", "path": "/var/www/html/.cache.php" },
  "process": {
    "pid": 18120, "ppid": 17801,
    "comm": "php-fpm", "exe": "/usr/sbin/php-fpm8.2",
    "uid": 33, "ancestors": ["nginx","systemd"]
  },
  "file": {
    "sha256": "5e...", "size": 2148, "mode": "0644",
    "owner": "www-data", "mtime": "2026-04-24T19:20:51Z"
  },
  "container": { "runtime": "containerd", "id": "9f2b...", "pod_uid": "ce..." },
  "signals": ["WEB_SHELL_PATTERN","ENTROPY_HIGH","WEB_TAINT_FLOW"],
  "evidence": { "matched_patterns": ["eval\\("], "entropy": 6.7 },
  "ioc_matches": []
}
```

## stdout

Always on. Forward via journald, vector, fluent-bit, etc., as a backup channel even when other sinks are configured.

```bash
journalctl -u ghostcatcher -o cat | jq 'select(.severity=="critical")'
```

## UDP syslog

Implementation: [`internal/export/syslog`](https://github.com/sercanokur/GhostCatcherEDR/tree/main/internal/export/syslog).

```yaml
syslog_udp:
  enabled: true
  host: siem-collector.internal
  port: 5514
  format: rfc5424          # or rfc3164
  facility: local0         # auth, authpriv, daemon, local0..local7
  app_name: ghostcatcher
  hostname: web-prod-01    # optional; otherwise the OS hostname
  max_msg_bytes: 8192
```

Notes:
- PRI is computed from `facility` plus the event severity (critical → 2, high → 3, medium → 4, low → 5, info → 6).
- The full JSON event lives in the syslog `MSG` field. Configure your SIEM parser to JSON-decode the substring after the RFC5424 header.
- UDP is best-effort. Use TCP for guaranteed delivery on noisy networks.

## TCP / TLS syslog (RFC5425)

Implementation: [`internal/export/syslogtcp`](https://github.com/sercanokur/GhostCatcherEDR/tree/main/internal/export/syslogtcp). Octet-counted framing — every message is prefixed with its byte length.

```yaml
syslog_tcp:
  enabled: true
  address: siem-collector.internal:6514
  tls: true
  ca_file: /etc/ghostcatcher/ca.pem
  cert_file: /etc/ghostcatcher/client.pem    # optional mTLS
  key_file: /etc/ghostcatcher/client.key     # optional mTLS
  server_name: siem-collector.internal       # SNI
  app_name: ghostcatcher
  facility: local0
  max_msg_bytes: 65535
```

The transport reconnects with exponential backoff on `EOF` / write errors and replays the spool on the next successful write.

## Splunk HEC

Implementation: [`internal/export/splunk`](https://github.com/sercanokur/GhostCatcherEDR/tree/main/internal/export/splunk).

```yaml
splunk_hec:
  enabled: true
  url: https://splunk.internal:8088/services/collector
  token: "${SPLUNK_HEC_TOKEN}"
  sourcetype: ghostcatcher:event
  source: ghostcatcher
  index: security
  insecure_skip_verify: false
  ca_file: /etc/ghostcatcher/splunk-ca.pem    # optional
```

Splunk receives:

```json
{
  "time": 1745525853,
  "host": "web-prod-01",
  "source": "ghostcatcher",
  "sourcetype": "ghostcatcher:event",
  "index": "security",
  "event": { "...the full event..." }
}
```

## Elasticsearch `_bulk`

Implementation: [`internal/export/elastic`](https://github.com/sercanokur/GhostCatcherEDR/tree/main/internal/export/elastic).

```yaml
elastic_bulk:
  enabled: true
  url: https://es.internal:9200
  index: ghostcatcher-events
  api_key: "${ES_API_KEY}"          # OR use basic auth below
  username: ""
  password: ""
  ca_file: /etc/ghostcatcher/es-ca.pem
  flush_interval: 1s
  flush_max_events: 50
```

Sends NDJSON:

```json
{"index":{"_index":"ghostcatcher-events"}}
{"@timestamp":"2026-04-24T19:21:33.018Z","rule_id":"WEB_SHELL_PATTERN","..."}
```

## Grafana Loki push

Implementation: [`internal/export/loki`](https://github.com/sercanokur/GhostCatcherEDR/tree/main/internal/export/loki).

```yaml
loki_push:
  enabled: true
  url: https://loki.internal/loki/api/v1/push
  tenant_id: security
  static_labels:
    job: ghostcatcher
    env: prod
  per_event_labels:
    - rule_id
    - severity
    - container_runtime
```

`per_event_labels` cherry-picks JSON fields and turns them into Loki labels. Keep this list short — high-cardinality labels (paths, hashes) hurt Loki performance.

## Spool format

`spool_dir/events.ndjson` (one JSON per line, append-only) plus a sibling rotation file when `spool_max_bytes` is reached. The runner replays in FIFO order on the first successful sink write per cycle.

To inspect:

```bash
sudo tail -f /var/spool/ghostcatcher/events.ndjson | jq 'select(.severity=="high")'
```

To force-drain (e.g. after restoring the SIEM connection) just restart the agent or trigger any sink-bound event; replays happen in-band.

## Choosing a sink set

| Goal | Suggested sinks |
|------|------------------|
| Single-host lab | stdout + UDP syslog to local rsyslog. |
| Standard SOC | TCP/TLS syslog (relay) + Splunk HEC for hot search. |
| Cloud-native | Loki for hot, Elastic for warm, stdout for journald rescue. |
| Air-gapped | stdout into a file collector, plus the spool as a buffer. |

## Failure cases

- **All sinks unhealthy** — events accumulate in the spool. Once the spool exceeds `spool_max_bytes` the oldest file is rotated out (ring buffer behavior). Stdout still receives every event so journald keeps a copy.
- **One sink wedged** — only that sink spools; others ship normally. The next successful write to the wedged sink drains.
- **Truncated UDP syslog** — events larger than `max_msg_bytes` are truncated. Prefer TCP/TLS for large evidence (e.g. PHP shell snippets in `evidence`).
- **Splunk/Elastic 401** — visible in agent stderr; spool keeps growing. Rotate the token, restart, spool drains.

Move on to **[Baselines and Learning Mode](Baselines-and-Learning-Mode)** to understand how to reduce false positives over time.
