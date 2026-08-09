# Rule Pack

The rule pack is a versioned YAML document that **scores** detections. Nano IDs and Macro/Micro metadata come from [`configs/mapping.yaml`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/configs/mapping.yaml); the pack supplies `base_score`, `expr`, pairwise `correlate`, and optional Act hints. You can add or tune rules without recompiling.

| Pack | Use |
|------|-----|
| [`configs/lab_rule_pack.yaml`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/configs/lab_rule_pack.yaml) | Full bhv catalog scoring (lab/demo) |
| [`configs/rule_pack.example.yaml`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/configs/rule_pack.example.yaml) | Production-oriented subset |

## File shape

```yaml
version: "2.0.0"
rules:
  - id: WEB_SHELL_PATTERN
    techniques: [T1505.003, T1059.004]
    tactic: persistence
    macro: M1
    micro: M1.1
    src: FIM
    type: STATE
    conf: MEDIUM
    min_signals: 2
    base_score: 55
    per_signal_bonus: 15
    cap_score: 100
    expr: confidence >= 55
    correlate: [WEB_WORKER_SHELL_CHILD, PROC_RARE_ANCESTRY]
    correlate_window: 30m
    correlate_boost: 15
    response:
      action: quarantine_file

  - id: CRON_HIGH_RISK
    techniques: [T1053.003]
    tactic: persistence
    macro: M2
    micro: M2.2
    src: FIM
    type: DELTA
    conf: HIGH
    min_signals: 1
    base_score: 60
    per_signal_bonus: 15
    cap_score: 100
    correlate: [WEB_WORKER_SHELL_CHILD, WEB_WORKER_INTERP_CHILD, WEB_DOCROOT_EXEC_WRITE]
    correlate_window: 30m
    correlate_boost: 20
```

### Rule fields

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `id` | string | yes | Nano ID → event `rule_id`. |
| `techniques` | list | yes | MITRE ATT&CK technique IDs. |
| `tactic` | string | no | ATT&CK tactic slug. |
| `macro` / `micro` | string | no | bhv taxonomy; filled from mapping when empty. |
| `src` | string | no | `EBPF-EXEC` \| `AUDIT` \| `FIM` \| `PROCSCAN` \| `INVENTORY` \| … |
| `type` | string | no | `EVENT` \| `DELTA` \| `STATE`. |
| `conf` | string | no | Standalone band `HIGH` \| `MEDIUM` \| `LOW`. |
| `min_signals` | int | yes | Minimum named signals before scoring. |
| `base_score` / `per_signal_bonus` / `cap_score` | int | no | Confidence scoring knobs. |
| `expr` | string | no | If false → force `learning_only`. |
| `correlate` | list | no | Peer nanos; same **anchor** (preferred) or entity within window. |
| `correlate_window` | duration | no | Default `5m`. |
| `correlate_boost` | int | no | Default `10`. |
| `kill_chain_phase` | string | no | Overrides tactic-derived Lockheed phase. |
| `response.action` | string | no | `alert_only` \| `quarantine_file` \| `kill_process` \| `isolate_host`. |

Events are schema **1.3**. Ordered CHAIN-1…6 definitions live in `mapping.yaml` (evaluated in `internal/runner/correlation.go` in addition to pairwise `correlate`).

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
| `signal("name")` | bool | True if `signals[]` contains that token (prefix match supported for `foo:bar`). |
| `technique("T…")` | bool | True if listed in `technique_id`. |
| `confidence` | int | Current score before Act. |
| `severity` | string | `info`…`critical`. |
| `comm` / `uid` / `euid` | | From process context when present. |
| `entity_path` / `entity_id` | string | Entity identifiers. |
| `container_runtime` | string | When classified. |
| `kill_chain_phase` | string | After Orient. |

## Pairwise correlation vs chains

- **Pairwise** (`correlate:` on a rule): peer fired recently on same anchor/entity → `correlate_boost` + signal `correlation_boost`.
- **Chains** (`mapping.yaml` `chains:`): ordered steps; current event must advance the chain; boost + `chain_id` + optional `evidence_loss` + severity CRITICAL.

Prefer anchors (systemd unit) over bare entity IDs so web-worker children correlate with later persistence on the same host unit.

## Sigma-lite drop-ins

`sigma_lite_dir` merges additional YAML after the primary pack. Unsupported Sigma features warn at load. IDs are uppercased with hyphens → underscores to match nano style.

## Signing

When `rule_pack_pubkey_file` and `rule_pack_signature_file` are set, `LoadPack` fail-closes on bad ed25519 detached signatures.

## Cross-references

- **[Behavior Taxonomy](Behavior-Taxonomy)** — catalog and chains.
- **[Detections](Detections)** — nano inventory.
- **[Configuration](Configuration)** — pack / mapping paths.
