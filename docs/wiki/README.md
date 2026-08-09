# GhostCatcher Wiki Source

This directory holds the **source** of the GitHub Wiki for GhostCatcher. GitHub stores every wiki as a separate Git repository at `https://github.com/sercanokur/GhostCatcherEDR.wiki.git`. The pages here are kept in the main repo so they can be reviewed via pull request and stay in sync with the code.

## Layout

| File | Purpose |
|------|---------|
| `Home.md` | Wiki landing page. |
| `_Sidebar.md` | Right-hand navigation sidebar (special name). |
| `_Footer.md` | Footer rendered on every page (special name). |
| `Getting-Started.md` | First install + first scan. |
| `Architecture.md` | Component map, packages, schema 1.3 pipeline. |
| `Behavior-Taxonomy.md` | Macro → Micro → Nano, anchors, CHAIN-1…6. |
| `Doctrine.md` | OODA, Kill Chain, ATT&CK, defense-in-depth + behavior tree. |
| `Detections.md` | Nano inventory by macro. |
| `Sensors.md` | eBPF / auditd / proc-poll + live nano routing. |
| `Rule-Pack.md` | Scoring YAML, expressions, correlation, signing. |
| `Configuration.md` | YAML keys (`mapping_path`, `watched_units`, …). |
| `Sinks-and-SIEM.md` | Schema 1.3 payload + transports. |
| `Baselines-and-Learning-Mode.md` | Snapshot lifecycle, golden-image note, 2FA. |
| `Quarantine-and-Self-Guard.md` | Evidence vault + agent self-integrity. |
| `Evaluation-Harness.md` | `ghostcatcher eval`, corpus, CI gating. |
| `Build-Tags.md` | `with_yara`, `with_ebpf`. |
| `Operations-Runbook.md` | Day-2 operations. |
| `Troubleshooting.md` | Common failure modes. |
| `FAQ.md` | Quick answers. |

Canonical behavior tree in the main repo: [`bhv.md`](../../bhv.md), machine catalog [`configs/mapping.yaml`](../../configs/mapping.yaml).

GitHub Wiki naming rules: spaces in titles become hyphens in filenames; the title rendered to readers is taken from the H1 (`#`) at the top of each page.

## Publishing

```bash
git clone https://github.com/sercanokur/GhostCatcherEDR.wiki.git ghostcatcher.wiki
cd ghostcatcher.wiki

rsync -a --delete \
  --exclude README.md \
  /path/to/GhostCatcherEntpointDetection/docs/wiki/ ./

git add -A
git commit -m "Sync wiki from main repo"
git push
```

## Conventions

- Every page starts with an `# H1 Title` matching the filename (hyphens → spaces).
- Cross-links use bare page names, e.g. `[Sensors](Sensors)`.
- Keep nano IDs synchronized with `configs/mapping.yaml` and `internal/detect/*/`.
- When you add a YAML config key, update `configs/config.example.yaml` and `Configuration.md` in the same PR.
- When you rename a `rule_id`, update **Detections**, **Sinks-and-SIEM** (rename table), and demo-console strings.
