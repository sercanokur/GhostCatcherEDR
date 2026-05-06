# Operations Runbook

Day-2 procedures for running GhostCatcher in production. Each section is a self-contained checklist you can copy into your wiki, ticketing system, or runbook.

## Pre-deployment checklist

- [ ] Distro and kernel version recorded; eBPF and YARA decisions made (see **[Build Tags](Build-Tags)**).
- [ ] Binary installed at `/usr/local/bin/ghostcatcher` with the correct mode (`0755`, root-owned).
- [ ] `selfguard.expected_sha256` pinned to the SHA-256 of the deployed binary.
- [ ] Config under `/etc/ghostcatcher/` (`0640`, root-owned), validated with `ghostcatcher check-config`.
- [ ] Rule pack signed; public key + signature path set in config.
- [ ] At least one sink (typically TCP/TLS syslog or HEC) reachable from the host.
- [ ] Baseline path on local disk with enough free space (the snapshot grows linearly with `document_roots`).
- [ ] `systemd` unit installed with `Type=notify` + `WatchdogSec=` if you want self-guard restarts.
- [ ] Operator on call has access to the secret used by `baseline_commit_token_env`.

## First baseline

```bash
sudo ghostcatcher check-config -config /etc/ghostcatcher/config.yaml
sudo ghostcatcher baseline commit -config /etc/ghostcatcher/config.yaml \
     ${GC_BASELINE_TOKEN:+-token "$GC_BASELINE_TOKEN"}
sudo systemctl enable --now ghostcatcher.service
journalctl -u ghostcatcher -n 50 --no-pager
```

Confirm the first scan completes without error and a non-empty stream of `learning_only` events appears in your SIEM.

## Rolling out a new rule pack

1. Author the rule on a feature branch with positive + negative samples in `testdata/eval/`.
2. CI runs `ghostcatcher eval -min-f1 ...`. Merge only on green.
3. Tag a release. Sign the new pack:

   ```bash
   openssl pkeyutl -sign -inkey /secure/rulepack.key \
     -in dist/rule_pack.yaml \
     -out dist/rule_pack.yaml.sig
   ```

4. Push `dist/rule_pack.yaml` and `dist/rule_pack.yaml.sig` to your config-management repo.
5. Roll to a canary host first; watch its alert rate for 24 h.
6. Roll out to the rest of the fleet. After each batch:

   ```bash
   sudo ghostcatcher check-config -config /etc/ghostcatcher/config.yaml
   sudo systemctl reload ghostcatcher.service     # or restart if reload not handled
   ```

## Rotating the baseline (planned change)

Triggered by deployments, package updates, kernel modules added, etc.

```bash
# 1. Snapshot the existing baseline for rollback / forensics.
sudo cp /var/lib/ghostcatcher/baseline.json \
        /var/lib/ghostcatcher/baseline.$(date -u +%Y%m%dT%H%M%S).json

# 2. Stop the agent so it does not race with the commit.
sudo systemctl stop ghostcatcher.service

# 3. Commit the new baseline (with 2FA if enabled).
GC_BASELINE_TOKEN="$(vault kv get -field=token kv/ghostcatcher/2fa)" \
  sudo -E ghostcatcher baseline commit \
       -config /etc/ghostcatcher/config.yaml \
       -token "$GC_BASELINE_TOKEN"

# 4. Restart.
sudo systemctl start ghostcatcher.service
journalctl -u ghostcatcher -n 50 --no-pager
```

Do **not** rotate the baseline during incident response unless you are deliberately archiving the “poisoned” snapshot and starting fresh from a known-good restore.

## Refreshing IOC feeds

GhostCatcher reads `ioc_feed_dir` on a schedule (`ioc_refresh_interval`, default `15m`). To force-refresh:

```bash
# 1. Pull / generate updated lists into a staging area.
sudo install -m 0644 -t /etc/ghostcatcher/ioc/hash    /tmp/new_hashes.txt
sudo install -m 0644 -t /etc/ghostcatcher/ioc/ip      /tmp/new_ips.txt
sudo install -m 0644 -t /etc/ghostcatcher/ioc/domain  /tmp/new_domains.txt

# 2. Touch the dir so the next refresh definitely re-reads.
sudo touch /etc/ghostcatcher/ioc

# 3. (Optional) restart for an immediate reload.
sudo systemctl restart ghostcatcher.service
```

Validate by running `journalctl -u ghostcatcher -g ioc.feed.loaded` — the agent logs counts on each refresh.

## Rotating the rule-pack signing key

1. Generate a new key on the build host (or HSM).
2. Sign the current rule pack with the **new** key.
3. Stage both old and new public keys on every host:

   ```yaml
   rule_pack_pubkey_files:
     - /etc/ghostcatcher/rulepack.pub.v1
     - /etc/ghostcatcher/rulepack.pub.v2
   ```

   (If you only have a single `rule_pack_pubkey_file`, switch to the new key first on hosts already running the new signature.)

4. Push the new signed pack everywhere.
5. Once every host runs successfully on the new key, remove the old `*.pub.v1`.

The agent verifies any pubkey in the list — useful for zero-downtime rotation.

## Rotating the `selfguard` hash after upgrade

Whenever the agent binary changes, the expected hash must change with it.

```bash
SHA="$(sha256sum /usr/local/bin/ghostcatcher | awk '{print $1}')"
sudo sed -i "s|expected_sha256: .*|expected_sha256: \"$SHA\"|" \
     /etc/ghostcatcher/config.yaml
sudo systemctl restart ghostcatcher.service
```

Bake this into the same package post-install hook that drops the binary.

## Quarantine archive

Daily, off-host:

```bash
ssh root@host "tar -C /var/lib/ghostcatcher -czf - quarantine" \
  | gpg --encrypt --recipient ir@yourorg \
  > /secure/quarantine/$host-$(date -u +%Y%m%d).tar.gz.gpg
```

After successful archive, prune the on-host vault:

```bash
sudo find /var/lib/ghostcatcher/quarantine \
     -mindepth 1 -maxdepth 1 -type d -mtime +30 -exec rm -rf {} +
```

(Adjust retention to your IR policy.)

## Spool inspection

If sinks have been unreachable, the spool is the source of truth.

```bash
sudo wc -l /var/spool/ghostcatcher/events.ndjson
sudo tail -f /var/spool/ghostcatcher/events.ndjson \
  | jq 'select(.severity=="critical")'
```

Once the sink is healthy again, the spool drains automatically. To force a drain immediately:

```bash
sudo systemctl restart ghostcatcher.service
```

## Stop / disable

```bash
# Temporary
sudo systemctl stop ghostcatcher.service

# Disable on boot (keeps config / baseline)
sudo systemctl disable --now ghostcatcher.service

# Hard-prevent any start
sudo systemctl mask ghostcatcher.service
sudo systemctl unmask ghostcatcher.service   # to undo
```

When stopped, the agent leaves all on-disk state in place. To remove entirely:

```bash
sudo systemctl disable --now ghostcatcher.service
sudo rm -f /etc/systemd/system/ghostcatcher.service
sudo rm -f /usr/local/bin/ghostcatcher
sudo rm -rf /etc/ghostcatcher /var/lib/ghostcatcher /var/spool/ghostcatcher
sudo systemctl daemon-reload
```

## Incident response sequence (host showed alerts)

1. **Do not rotate the baseline.** It would absorb attacker artifacts as known good.
2. Snapshot the relevant artifacts:

   ```bash
   sudo journalctl -u ghostcatcher --since "24 hours ago" > /tmp/ghostcatcher.log
   sudo tar -czf /tmp/quarantine.tgz -C /var/lib/ghostcatcher quarantine
   sudo cp /var/lib/ghostcatcher/baseline.json /tmp/
   ```

3. Pull `/proc` triage data while the host is live (process tree, `ss -tnap`, `ps auxf`).
4. Once IR has its evidence, isolate or rebuild the host per your runbook.
5. After rebuild + restoration to a known-good state, run the **first baseline** procedure above, not “rotate baseline.”

## Escalation matrix

| Symptom | First check | Escalate to |
|---------|-------------|-------------|
| `AGENT_TAMPERED` | Compare `sha256sum /usr/local/bin/ghostcatcher` to the expected hash; check change windows for a planned upgrade. | Security on-call. |
| Spool growing without bound | Sink health (`journalctl -u ghostcatcher | grep sink`); credentials / network reachability. | Platform on-call. |
| Burst of `WEB_SHELL_PATTERN` after deploy | Was it a planned content release? Add `path_allowlist_prefixes` and rotate baseline if confirmed benign. | App team owner. |
| eBPF backend dropping events | Kernel ringbuffer overrun (`grep ringbuffer.overrun` in journal). | Increase `sensor.debounce_ms`, raise host scan capacity, or pin to auditd. |
| Repeated `INTEGRITY_DRIFT` on `/usr/bin/ls` after package update | Update happened outside of GhostCatcher's awareness. Re-baseline integrity paths after confirming the update is legitimate. | Platform on-call. |

## Useful one-liners

```bash
# What is the agent doing right now?
journalctl -u ghostcatcher -f -o cat | jq -r '"\(.timestamp) \(.severity) \(.rule_id) \(.entity.path // .entity.id)"'

# How many alerts per rule today?
journalctl -u ghostcatcher --since today -o cat | jq -r .rule_id | sort | uniq -c | sort -nr

# Show only critical events from the spool
sudo jq 'select(.severity=="critical")' /var/spool/ghostcatcher/events.ndjson

# Confirm rule pack signature is current
openssl pkeyutl -verify -pubin -inkey /etc/ghostcatcher/rulepack.pub \
  -in /etc/ghostcatcher/rule_pack.yaml \
  -sigfile /etc/ghostcatcher/rule_pack.yaml.sig
```
