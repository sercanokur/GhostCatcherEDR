package web

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/procfs"
	"ghostcatcher/internal/rules"
)

const RuleWebReconChild = "WEB_WORKER_RECON_CHILD"

// Post-exploit / auditd-style recon often spawned under web workers (approximates "www-data running whoami").
var reconArgvPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bwhoami\b`),
	regexp.MustCompile(`(?i)\bifconfig\b`),
	regexp.MustCompile(`(?i)\buname(\s+|$)`),
	regexp.MustCompile(`(?i)\bid(\s+|$)`),
	regexp.MustCompile(`(?i)\bhostname(\s+|$)`),
	regexp.MustCompile(`(?i)\bnetstat\b`),
	regexp.MustCompile(`(?i)\biptables\b`),
	regexp.MustCompile(`(?i)\bip\s+addr\b`),
	regexp.MustCompile(`(?i)/usr/sbin/ss\b`),
	regexp.MustCompile(`(?i)\bawk\b.*/etc/passwd`),
}

// ScanReconChildren emits findings when a web server worker has a child whose argv matches common recon binaries (host-level stand-in for auditd syscall rules).
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
	for wpid := range workers {
		if hit, childPID, exe, argv := findReconChild(wpid, 0, 5); hit {
			sigs := []string{"web_worker_recon_child", "parent_worker_pid:" + strconv.Itoa(wpid)}
			if exe != "" {
				sigs = append(sigs, "child_exe:"+exe)
			}
			conf, _ := rules.Score(pack, RuleWebReconChild, sigs)
			ev := event.Event{
				SchemaVersion:   event.SchemaVersion,
				AgentVersion:    agentVer,
				Timestamp:       now,
				RuleID:          RuleWebReconChild,
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
				Evidence:     truncateStr(argv, 400),
				LearningOnly: learning || conf < cfg.MinConfidenceAlert,
			}
			ev.NormalizeDedup()
			events = append(events, ev)
		}
	}
	return events, nil
}

func findReconChild(pid int, depth, max int) (bool, int, string, string) {
	if depth > max {
		return false, 0, "", ""
	}
	kids, err := procfs.Children(pid)
	if err != nil {
		return false, 0, "", ""
	}
	for _, c := range kids {
		argv, _ := procfs.Cmdline(c)
		line := strings.Join(argv, " ")
		for _, re := range reconArgvPatterns {
			if re.MatchString(line) {
				return true, c, procfs.ResolveExe(c), line
			}
		}
		if ok, cp, exe, a := findReconChild(c, depth+1, max); ok {
			return true, cp, exe, a
		}
	}
	return false, 0, "", ""
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
