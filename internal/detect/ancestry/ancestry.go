// Package ancestry detects unusual process lineage such as a web server
// directly spawning a shell. The detector walks /proc once per scan and
// compares each observed (parent_comm, child_comm) pair against the
// baseline; unseen combinations for a short allowlist of "juicy" parents
// become PROC_RARE_ANCESTRY events.
package ancestry

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/procfs"
	"ghostcatcher/internal/rules"
)

const RuleRareAncestry = "PROC_RARE_ANCESTRY"

// juicyParents is the set of parent comms whose children we audit. Adding
// every parent would be too noisy; this list focuses on surfaces that
// attackers repeatedly abuse.
var juicyParents = map[string]struct{}{
	"nginx":     {},
	"apache2":   {},
	"httpd":     {},
	"php-fpm":   {},
	"php":       {},
	"tomcat":    {},
	"java":      {},
	"node":      {},
	"mysqld":    {},
	"postgres":  {},
	"sshd":      {},
	"cron":      {},
	"crond":     {},
	"systemd":   {},
	"containerd": {},
	"dockerd":   {},
	"runc":      {},
}

// suspiciousChildren are comms that, when spawned by a juicy parent we have
// never seen before, look like post-exploitation.
var suspiciousChildren = map[string]struct{}{
	"sh": {}, "bash": {}, "dash": {}, "zsh": {}, "ksh": {},
	"nc": {}, "ncat": {}, "socat": {},
	"curl": {}, "wget": {},
	"python": {}, "python3": {}, "perl": {}, "ruby": {},
	"nmap": {}, "whoami": {}, "id": {},
	"base64": {}, "xxd": {},
	"awk": {}, "sed": {},
}

// Scan walks the process table once and returns events for every unseen
// parent→child pair that also targets one of the juicyParents.
func Scan(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string) ([]event.Event, error) {
	pids, err := procfs.Processes()
	if err != nil {
		// Non-Linux hosts (dev machines) do not expose /proc. Treat it as
		// an empty process set rather than surfacing the error so the rest
		// of the scan continues.
		return nil, nil
	}
	seen := make(map[string]struct{}, len(snap.ProcessAncestry))
	for _, p := range snap.ProcessAncestry {
		seen[p] = struct{}{}
	}
	now := time.Now().UTC()
	var events []event.Event
	for _, pid := range pids {
		comm, err := procfs.Comm(pid)
		if err != nil || comm == "" {
			continue
		}
		if _, ok := suspiciousChildren[comm]; !ok {
			continue
		}
		ppid, err := procfs.PPid(pid)
		if err != nil || ppid <= 0 {
			continue
		}
		pcomm, err := procfs.Comm(ppid)
		if err != nil || pcomm == "" {
			continue
		}
		if _, ok := juicyParents[pcomm]; !ok {
			continue
		}
		pair := pcomm + "\x00" + comm
		if _, ok := seen[pair]; ok {
			continue
		}
		signals := []string{"rare_ancestry", "juicy_parent:" + pcomm, "suspicious_child:" + comm}
		conf, _ := rules.Score(pack, RuleRareAncestry, signals)
		if conf == 0 {
			conf = 70
		}
		sev := rules.SeverityFromConfidence(conf, cfg.LearningMode)
		argv, _ := procfs.Cmdline(pid)
		ev := event.Event{
			SchemaVersion:   event.SchemaVersion,
			AgentVersion:    agentVer,
			Timestamp:       now,
			RuleID:          RuleRareAncestry,
			RulePackVersion: pack.Version,
			TechniqueIDs:    []string{"T1059"},
			Tactic:          "execution",
			Confidence:      conf,
			Severity:        sev,
			Entity: event.Entity{
				Type: event.EntityProcess,
				ID:   fmt.Sprintf("%d", pid),
				Path: strings.Join(argv, " "),
			},
			Signals:      signals,
			Evidence:     fmt.Sprintf("%s(pid=%d) -> %s(ppid=%d) unseen in baseline", comm, pid, pcomm, ppid),
			LearningOnly: cfg.LearningMode,
		}
		events = append(events, ev)
	}
	return events, nil
}

// BuildBaselineAncestry snapshots every currently observable
// (parent_comm, child_comm) pair. Called from `ghostcatcher baseline commit`.
func BuildBaselineAncestry() ([]string, error) {
	pids, err := procfs.Processes()
	if err != nil {
		return nil, err
	}
	set := map[string]struct{}{}
	for _, pid := range pids {
		comm, err := procfs.Comm(pid)
		if err != nil {
			continue
		}
		ppid, err := procfs.PPid(pid)
		if err != nil || ppid <= 0 {
			continue
		}
		pcomm, err := procfs.Comm(ppid)
		if err != nil {
			continue
		}
		set[pcomm+"\x00"+comm] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}
