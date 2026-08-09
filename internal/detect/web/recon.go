package web

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"ghostcatcher/internal/anchor"
	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/procfs"
	"ghostcatcher/internal/rules"
)

const (
	RuleWebReconChild      = "WEB_WORKER_RECON_CHILD"
	RuleWebShellChild      = "WEB_WORKER_SHELL_CHILD"
	RuleWebInterpChild     = "WEB_WORKER_INTERP_CHILD"
	RuleWebDownloaderChild = "WEB_WORKER_DOWNLOADER_CHILD"
	RuleProcPtySpawn       = "PROC_PTY_SPAWN"
)

var reconArgvPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bwhoami\b`),
	regexp.MustCompile(`(?i)\bifconfig\b`),
	regexp.MustCompile(`(?i)\buname(\s+|$)`),
	regexp.MustCompile(`(?i)\bid(\s+|$)`),
	regexp.MustCompile(`(?i)\bhostname(\s+|$)`),
	regexp.MustCompile(`(?i)\bnetstat\b`),
	regexp.MustCompile(`(?i)\biptables\b`),
	regexp.MustCompile(`(?i)\bip\s+addr\b`),
	regexp.MustCompile(`(?i)\bss(\s+|$)`),
	regexp.MustCompile(`(?i)\bps(\s+|$)`),
	regexp.MustCompile(`(?i)\bfind(\s+|$)`),
	regexp.MustCompile(`(?i)\bcat\s+/etc/passwd`),
}

var shellBasenames = map[string]struct{}{
	"sh": {}, "bash": {}, "dash": {}, "zsh": {}, "ksh": {},
}

var downloaderBasenames = map[string]struct{}{
	"curl": {}, "wget": {}, "nc": {}, "ncat": {}, "netcat": {},
	"socat": {}, "ftp": {}, "tftp": {}, "busybox": {},
}

var interpFlag = regexp.MustCompile(`(?i)\b(python[0-9.]*|perl|php|ruby|node|nodejs)\b.*\s(-c|-e|-r)\b`)

var ptySpawn = regexp.MustCompile(`(?i)(pty\.spawn|openpty|script\s+-qc|python.*pty)`)

// ScanReconChildren emits M1.2 nanos for web-worker children (recon/shell/interp/downloader/pty).
func ScanReconChildren(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string) ([]event.Event, error) {
	if !cfg.WebReconChildScanEnabled {
		return nil, nil
	}
	var events []event.Event
	now := time.Now().UTC()
	learning := cfg.LearningMode || !snap.IsCommitted()
	if cfg.FirstRunAllowAlerts {
		learning = cfg.LearningMode
	}

	workers := findWebWorkerPIDs(cfg)
	seen := map[string]struct{}{}
	for wpid := range workers {
		ainfo := anchor.FromPID(wpid)
		walkWorkerChildren(wpid, 0, 5, func(childPID int, exe, line string) {
			ruleID, sig := classifyWebChild(exe, line)
			if ruleID == "" {
				return
			}
			key := ruleID + ":" + strconv.Itoa(childPID)
			if _, ok := seen[key]; ok {
				return
			}
			seen[key] = struct{}{}
			sigs := []string{sig, "parent_worker_pid:" + strconv.Itoa(wpid)}
			if ainfo.SystemdUnit != "" {
				sigs = append(sigs, "parent_unit:"+ainfo.SystemdUnit)
			}
			if exe != "" {
				sigs = append(sigs, "child_exe:"+exe)
			}
			conf, _ := rules.Score(pack, ruleID, sigs)
			if conf < 70 {
				conf = 70
			}
			ev := event.Event{
				SchemaVersion:   event.SchemaVersion,
				AgentVersion:    agentVer,
				Timestamp:       now,
				RuleID:          ruleID,
				RulePackVersion: pack.Version,
				TechniqueIDs:    []string{"T1059.004", "T1505.003"},
				Tactic:          "execution",
				Confidence:      conf,
				Severity:        rules.SeverityFromConfidence(conf, learning),
				Entity: event.Entity{
					Type: event.EntityProcess,
					ID:   strconv.Itoa(childPID),
					Path: exe,
				},
				Signals:      sigs,
				Evidence:     truncateStr(line, 400),
				LearningOnly: learning || conf < cfg.MinConfidenceAlert,
				Src:          event.SrcProcScan, // honest until live eBPF exec wired
				Type:         event.TypeEvent,
				Anchor:       ainfo.Anchor,
				ConfBand:     event.ConfHigh,
			}
			ev.NormalizeDedup()
			events = append(events, ev)
		})
	}
	return events, nil
}

func classifyWebChild(exe, line string) (ruleID, signal string) {
	base := strings.ToLower(filepath.Base(exe))
	if base == "" {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			base = strings.ToLower(filepath.Base(fields[0]))
		}
	}
	if ptySpawn.MatchString(line) {
		return RuleProcPtySpawn, "web_worker_pty_spawn"
	}
	if _, ok := shellBasenames[base]; ok {
		return RuleWebShellChild, "web_worker_shell_child"
	}
	if interpFlag.MatchString(line) {
		return RuleWebInterpChild, "web_worker_interp_child"
	}
	if _, ok := downloaderBasenames[base]; ok {
		if base == "busybox" && !strings.Contains(strings.ToLower(line), "wget") {
			// busybox without wget is not a downloader signal alone
		} else {
			return RuleWebDownloaderChild, "web_worker_downloader_child"
		}
	}
	for _, re := range reconArgvPatterns {
		if re.MatchString(line) {
			return RuleWebReconChild, "web_worker_recon_child"
		}
	}
	return "", ""
}

func walkWorkerChildren(pid, depth, max int, fn func(childPID int, exe, line string)) {
	if depth > max {
		return
	}
	kids, err := procfs.Children(pid)
	if err != nil {
		return
	}
	for _, c := range kids {
		argv, _ := procfs.Cmdline(c)
		line := strings.Join(argv, " ")
		exe := procfs.ResolveExe(c)
		fn(c, exe, line)
		walkWorkerChildren(c, depth+1, max, fn)
	}
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
