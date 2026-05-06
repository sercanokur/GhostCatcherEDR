# Evaluation Harness

`ghostcatcher eval` is the agent's built-in detection-quality harness. It runs the real detection code over a labeled corpus on disk and reports precision, recall, and F1. CI uses it as a regression gate so a rule pack change that improves recall while quietly destroying precision (or vice versa) cannot merge.

Implementation: [`internal/eval`](https://github.com/sercanokur/GhostCatcherEDR/tree/main/internal/eval) and [`cmd/agent/main.go`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/cmd/agent/main.go) → `evalCmd`.

## Corpus layout

```
testdata/eval/
├── malicious/
│   ├── china_chopper.php
│   ├── concat_obfuscation.php
│   ├── runtime_exec.jsp
│   ├── process_start.aspx
│   └── ...
├── benign/
│   ├── laravel_router.php
│   ├── wordpress_index.php
│   ├── jsp_status.jsp
│   └── ...
└── cron/
    ├── malicious/
    │   ├── b64_payload.txt
    │   └── dev_tcp.txt
    └── benign/
        ├── logrotate.txt
        └── certbot.txt
```

Rules:

- One sample per file. The harness counts files, not bytes.
- Filenames must be unique across `malicious/` and `benign/` (used as identifiers in the report).
- `cron/` has its own malicious / benign split because cron lines are scanned line-by-line, not as files.

You can supply your own corpus with `-corpus /path/to/your/corpus` and the same layout.

## Running

```bash
ghostcatcher eval -corpus testdata/eval
```

Output:

```
== ghostcatcher eval ==
corpus: testdata/eval
samples: 14 (malicious=8, benign=6)

      | predicted_alert | predicted_clean
------+-----------------+-----------------
mal   |              7  |              1
ben   |              0  |              6

precision : 1.000
recall    : 0.875
f1        : 0.933
```

To fail the run when F1 drops below a floor:

```bash
ghostcatcher eval -corpus testdata/eval -min-f1 0.85
echo "exit: $?"     # 0 if F1 >= 0.85, 1 otherwise
```

## How it works

1. Loads the default config but forces `LearningMode=false`, `FirstRunAllowAlerts=true`, `MinConfidenceAlert=60` so every detector behaves as if it were running in production with no baseline.
2. For the web corpus: sets `DocumentRoots = [malicious_dir]`, calls `web.Scan` once, collects every emitted file path into a hit set; repeats with `[benign_dir]`.
3. For the cron corpus: parses each line through `persistence.EvalCronLine` (a thin wrapper exposed for the harness), and counts whether it produced a `CRON_RISK_LINE`-class event.
4. Aggregates TP / FP / FN / TN across both corpora and computes:

   ```
   precision = TP / (TP + FP)
   recall    = TP / (TP + FN)
   f1        = 2 * precision * recall / (precision + recall)
   ```

5. Prints a confusion-matrix-style report and exits with the appropriate code.

The harness deliberately calls `web.Scan` once per directory rather than once per file. Scanning a directory once exercises the same path that the production agent uses (the file-walk, baseline-aware logic, and dedup all matter), and avoids the false-negative inflation that came from re-scanning each file in isolation.

## Authoring new samples

When you add a detection — a new web shell pattern, a new cron token, a new persistence path — drop matched + non-matched examples into the corpus on the same PR.

Tips:

- Real-world malware samples are best. The shipped corpus deliberately contains widely-public test artifacts (China Chopper, Runtime.exec JSP, Process.Start ASPX) and not novel offensive code. Source equivalents from PoC repos and trim them to the smallest reproducer that still trips the rule.
- For benign samples, copy from real frameworks (Laravel, Symfony, WordPress, common JSP starters). The point is to *look* like the kind of file the rule could mis-fire on.
- Keep individual files small (< 32 KB) to keep the harness fast.

When the corpus changes you usually need to revisit `-min-f1`. Bump it up if quality has improved; do not lower it without an explanation in the PR description.

## Wiring into CI

The shipped GitHub Actions workflow ([`.github/workflows/ci.yml`](https://github.com/sercanokur/GhostCatcherEDR/blob/main/.github/workflows/ci.yml)) runs:

```yaml
- name: Detection regression
  run: |
    go run ./cmd/agent eval \
      -corpus testdata/eval \
      -min-f1 0.85
```

…right after `go test`, so failed regression blocks the merge. Adjust the floor in one place if your team raises the bar.

## Limitations

- Web shells: the harness only exercises the file-on-disk path. Memory-only payloads are out of scope (they require runtime sensors that are not represented in static corpora).
- Cron: only line-level evaluation, not full crontab interaction with `cron.allow` / `cron.deny`.
- Sensors: the harness does not currently replay eBPF / auditd traces. A trace replayer is a planned addition; for now, sensor regressions are caught by Go-level unit tests in `internal/sensor/`.
- Network and `/proc/maps` rules: not exercised by the harness because they need a live process. Evaluate them with integration tests inside a VM.

## Local iteration loop

```bash
# 1. Add or edit a rule in configs/rule_pack.example.yaml
# 2. Add positive + negative samples under testdata/eval/
# 3. Run the harness
go run ./cmd/agent eval -corpus testdata/eval

# 4. If F1 looks right, run the unit tests too
go test ./...

# 5. Commit, push, let CI rerun the harness with -min-f1 0.85
```

The harness is fast (< 1 s for the shipped corpus on a laptop), so keep it in your inner loop. If you need more granular numbers per rule, edit `internal/eval/eval.go` to break down hits by `rule_id` — this is intentionally a small, easy-to-extend file.
