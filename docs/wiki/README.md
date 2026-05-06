# GhostCatcher Wiki Source

This directory holds the **source** of the GitHub Wiki for GhostCatcher. GitHub stores every wiki as a separate Git repository at `https://github.com/sercanokur/GhostCatcherEDR.wiki.git`. The pages here are kept in the main repo so they can be reviewed via pull request and stay in sync with the code.

## Layout

| File | Purpose |
|------|---------|
| `Home.md` | Wiki landing page. |
| `_Sidebar.md` | Right-hand navigation sidebar (special name). |
| `_Footer.md` | Footer rendered on every page (special name). |
| `Getting-Started.md` | First install + first scan. |
| `Architecture.md` | High-level component map. |
| `Detections.md` | Per-rule detection coverage. |
| `Sensors.md` | eBPF / auditd / proc-poll backends. |
| `Rule-Pack.md` | Rule pack format, expressions, signing, Sigma-lite. |
| `Configuration.md` | Every YAML key explained. |
| `Sinks-and-SIEM.md` | UDP/TCP/TLS syslog, Splunk HEC, Elastic `_bulk`, Loki. |
| `Baselines-and-Learning-Mode.md` | What gets baselined, the learning workflow, 2FA. |
| `Quarantine-and-Self-Guard.md` | Evidence vault + agent self-integrity. |
| `Evaluation-Harness.md` | `ghostcatcher eval`, the corpus, CI gating. |
| `Build-Tags.md` | `with_yara`, `with_ebpf`, cgo flags. |
| `Operations-Runbook.md` | Day-2 operations: restarts, baseline rotation, IOC refresh. |
| `Troubleshooting.md` | Common failure modes. |
| `FAQ.md` | Quick answers. |

GitHub Wiki naming rules: spaces in titles become hyphens in filenames; the title rendered to readers is taken from the H1 (`#`) at the top of each page.

## Publishing

Wikis live in a sibling Git repository. To copy this directory into your wiki:

```bash
# 1. Clone the wiki repo (must be enabled in repository settings → Wikis)
git clone https://github.com/sercanokur/GhostCatcherEDR.wiki.git ghostcatcher.wiki
cd ghostcatcher.wiki

# 2. Sync the source pages from this directory
rsync -a --delete \
  --exclude README.md \
  /path/to/GhostCatcherEntpointDetection/docs/wiki/ ./

# 3. Commit and push
git add -A
git commit -m "Sync wiki from main repo"
git push
```

You can also automate this with a GitHub Action that triggers on any change under `docs/wiki/**` and force-pushes the contents to the wiki repo.

## Conventions

- Every page starts with an `# H1 Title` matching the filename (with hyphens replaced by spaces).
- Cross-links use the bare page name with hyphens, e.g. `[Sensors](Sensors)`.
- Code samples that exist in the repo are always cited with relative paths so readers can jump from the wiki back to source.
- Configuration snippets stay aligned with `configs/config.example.yaml`. When you add or rename a YAML key, update **both** the example file and `Configuration.md` in the same PR.
