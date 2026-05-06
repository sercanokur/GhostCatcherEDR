# Rule Pack

The rule pack is a versioned YAML document that describes every detection rule the agent ships. Detection logic is **data, not code** — you can add or tune rules without recompiling the agent. This page covers the schema, the boolean expression language, time-windowed correlation, Sigma-lite drop-ins, and ed25519 signing.

The reference example lives at [`configs/rule_pack.example.yaml`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/configs/rule_pack.example.yaml).

## File shape

```yaml
version: 2025.04.0
metadata:
  vendor: ghostcatcher
  description: Default detection set
  min_agent_version: "0.2.0"

rules:
  - id: WEB_SHELL_PATTERN
    technique: T1505.003
    tactic: persistence
    severity: high
    base_confidence: 60
    min_signals: 2
    weights:
      WEB_SHELL_PATTERN: 30
      WEB_TAINT_FLOW:    25
      ENTROPY_HIGH:      10
      MAGIC_MISMATCH:    10
      OWNERSHIP_WEB:     5
    expr: signal("WEB_SHELL_PATTERN") and confidence >= 70
    correlate: [PROC_RARE_ANCESTRY, NET_REVERSE_SHELL]
    correlate_window: 10m
    correlate_boost: 15
```

### Rule fields

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `id` | string | yes | Stable identifier emitted as `rule_id`. |
| `technique` | string | yes | MITRE ATT&CK ID, emitted as `technique_id`. |
| `tactic` | string | no | Free-form tactic label. |
| `severity` | enum | yes | `info` / `low` / `medium` / `high` / `critical`. |
| `base_confidence` | int | yes | Starting confidence applied to the event before signal weights. |
| `min_signals` | int | yes | Minimum number of named signals needed before the rule produces an event. |
| `weights` | map | no | Per-signal confidence contribution. Missing signals contribute zero. |
| `expr` | string | no | Boolean expression evaluated after weights; if false the event is downgraded to `learning_only`. |
| `correlate` | list | no | Peer rule IDs that, if seen on the same entity inside `correlate_window`, contribute `correlate_boost`. |
| `correlate_window` | duration | no | Go duration string (`30s`, `5m`, `1h`). Default `5m` if `correlate` is set. |
| `correlate_boost` | int | no | Confidence delta added on a correlated hit. Default `10`. |
| `dedup_window` | duration | no | Per-entity dedup. Defaults to `scan_interval`. |
| `learning_only` | bool | no | Force the rule to never alert; useful when staging a new detection. |

## Expression language

Implemented in [`internal/rules/expr.go`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/internal/rules/expr.go). The evaluator is purpose-built and intentionally small (no Turing-complete escape).

### Grammar

```text
expr     := orExpr
orExpr   := andExpr ("or"  andExpr)*
andExpr  := notExpr ("and" notExpr)*
notExpr  := "not" notExpr | cmpExpr
cmpExpr  := primary (cmpOp primary)?
cmpOp    := "==" | "!=" | "<" | "<=" | ">" | ">=" | "in" | "contains"
primary  := literal | identifier | call | "(" expr ")"
call     := identifier "(" args? ")"
args     := expr ("," expr)*
literal  := number | string | "true" | "false" | "null" | list
list     := "[" args? "]"
```

### Built-in functions

| Function | Returns | Notes |
|----------|---------|-------|
| `signal(name)` | bool | True if the candidate event carries that signal. |
| `technique(id)` | bool | True if the rule's technique matches. |
| `matches(value, regex)` | bool | RE2 regex match. |
| `contains(haystack, needle)` | bool | Substring match. |
| `startswith(s, prefix)` | bool | |
| `endswith(s, suffix)` | bool | |
| `len(x)` | int | Length of string or list. |

### Built-in identifiers

| Identifier | Type | Meaning |
|------------|------|---------|
| `confidence` | int | Current event confidence after weight + correlate. |
| `severity` | string | One of the severity enum values. |
| `entity_path` | string | File path, socket tuple, or process exe path. |
| `comm` | string | Process `comm`. |
| `parent_comm` | string | Parent process `comm`. |
| `cmdline` | string | Whole command line (space-joined argv). |
| `uid`, `euid`, `pid`, `ppid` | int | |
| `remote_ip`, `remote_port`, `local_ip`, `local_port` | string/int | |
| `container_runtime`, `container_id`, `pod_uid` | string | |
| `learning_only` | bool | Pre-evaluation flag. |

### Examples

```yaml
expr: signal("WEB_SHELL_PATTERN") and confidence >= 70

expr: comm in ["sh","bash","dash","ash","zsh"]
      and not parent_comm in ["systemd","init","tmux","sshd"]

expr: matches(entity_path, "^/tmp/.*\\.so$")
      or contains(entity_path, "/dev/shm/")

expr: technique("T1059.004") and confidence > 80
```

## Correlation

The runner keeps a sliding-window map of `(rule_id, entity_path) -> last_seen` (`internal/runner/correlation.go`). When a new event matches a rule whose `correlate` list contains a previously-seen rule on the same entity within `correlate_window`:

1. `correlate_boost` is added to the event's confidence.
2. A synthetic `CORRELATION_BOOST` signal is appended to `signals[]`.
3. The peer's `rule_id` is recorded in `evidence.correlated_with`.

This is how a single-signal cron edit can become high-confidence when paired with an outbound `nc` from the same host inside ten minutes.

## Sigma-lite drop-ins

GhostCatcher reads Sigma YAML files from `sigma_lite_dir` and transpiles a subset of the format into native rules. Implementation: [`internal/rules/sigma_lite.go`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/internal/rules/sigma_lite.go).

Supported subset:

- `detection.selection` blocks with `field: value`, `field|contains:`, `field|startswith:`, `field|endswith:`, `field|re:`.
- A single `condition: selection` (no nested boolean expressions yet — chain at the GhostCatcher rule level instead).
- `level` mapped to severity (`informational`/`low`/`medium`/`high`/`critical`).
- `id` mapped to `rule_id` (uppercased, hyphens to underscores), `tags` containing a `attack.tNNNN` mapped to `technique_id`.

Anything outside that subset is logged at WARN and skipped, so a partially-supported pack still loads.

Example:

```yaml
title: Suspicious base64 in cron
id: 5fae6c52-6f73-4a3a-9a96-ghostcatcher
status: experimental
level: high
tags: [attack.persistence, attack.t1053.003]
detection:
  selection:
    cmdline|contains:
      - "base64 -d"
      - "echo "
  condition: selection
```

## Signing

A rule pack can be signed with an ed25519 detached signature. Loading verification is implemented in [`internal/rules/verify.go`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/internal/rules/verify.go).

### Generate keys

```bash
openssl genpkey -algorithm Ed25519 -out rulepack.key
openssl pkey -in rulepack.key -pubout -outform DER \
  | tail -c 32 | base64 > /etc/ghostcatcher/rulepack.pub
```

Distribute `rulepack.pub` to every host. Keep `rulepack.key` on a build host or in a hardware token.

### Sign a pack

```bash
openssl pkeyutl -sign \
  -inkey rulepack.key \
  -in /etc/ghostcatcher/rule_pack.yaml \
  -out /etc/ghostcatcher/rule_pack.yaml.sig
```

### Configure the agent

```yaml
rule_pack_path: /etc/ghostcatcher/rule_pack.yaml
rule_pack_pubkey_file: /etc/ghostcatcher/rulepack.pub
rule_pack_signature_file: /etc/ghostcatcher/rule_pack.yaml.sig
```

If the signature does not validate (file tampered, wrong public key, missing files), `ghostcatcher run` exits non-zero before any detection runs. **There is no override flag.** Sigma-lite drop-ins from `sigma_lite_dir` are merged after the signed pack and are not signed by this mechanism — keep them in a directory only root can write.

## Authoring workflow

1. Add the rule (and any supporting detector code) on a feature branch.
2. Add labeled test cases to `testdata/eval/malicious/` (true positives) and `testdata/eval/benign/` (true negatives).
3. Run `ghostcatcher eval -corpus testdata/eval` and confirm the F1 score does not regress below your CI floor.
4. Open a PR. The CI workflow re-runs `ghostcatcher eval` with `-min-f1 0.85` and blocks merges on regression.
5. After merge, sign the new rule pack and roll it out via configuration management.

See **[Evaluation Harness](Evaluation-Harness)** for details on the harness.
