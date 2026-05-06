package ldpreload

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/procfs"
	"ghostcatcher/internal/rules"
)

const (
	RuleLdSoPreload   = "LD_SO_PRELOAD_FILE"
	RuleProcLDPreload = "PROC_LD_PRELOAD_ENV"
)

func Scan(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string) ([]event.Event, error) {
	var events []event.Event
	now := time.Now().UTC()
	learning := cfg.LearningMode || !snap.IsCommitted()
	if cfg.FirstRunAllowAlerts {
		learning = cfg.LearningMode
	}

	b, err := os.ReadFile("/etc/ld.so.preload")
	if err == nil {
		content := strings.TrimSpace(string(b))
		if content != "" && !allLinesAllowlisted(content, cfg.LDPreloadAllowlist) {
			sigs := []string{"ld_so_preload_non_empty", "not_in_allowlist"}
			conf, _ := rules.Score(pack, RuleLdSoPreload, sigs)
			if conf < 95 {
				conf = 95
			}
			tech := []string{"T1574.006", "T1014"}
			ev := event.Event{
				SchemaVersion:   event.SchemaVersion,
				AgentVersion:    agentVer,
				Timestamp:       now,
				RuleID:          RuleLdSoPreload,
				RulePackVersion: pack.Version,
				TechniqueIDs:    tech,
				Tactic:          "defense-evasion",
				Confidence:      conf,
				Severity:        rules.SeverityFromConfidence(conf, false),
				Entity:          event.Entity{Type: event.EntityFile, ID: "/etc/ld.so.preload", Path: "/etc/ld.so.preload"},
				Signals:         sigs,
				Evidence:        truncate(content, 300),
				LearningOnly:    false,
			}
			ev.NormalizeDedup()
			events = append(events, ev)
		}
	}

	pids, err := procfs.Processes()
	if err != nil {
		return events, nil
	}
	targets := map[string]struct{}{}
	for _, n := range cfg.TargetProcessNames {
		targets[strings.ToLower(n)] = struct{}{}
	}

	allowed := map[string]struct{}{}
	for _, v := range snap.LDPreload {
		allowed[v] = struct{}{}
	}

	for _, pid := range pids {
		comm, err := procfs.Comm(pid)
		if err != nil {
			continue
		}
		if _, ok := targets[strings.ToLower(strings.TrimSpace(comm))]; !ok {
			continue
		}
		env, err := procfs.Environ(pid)
		if err != nil {
			continue
		}
		v, ok := env["LD_PRELOAD"]
		if !ok || strings.TrimSpace(v) == "" {
			continue
		}
		if isAllowlistedValue(v, cfg.LDPreloadAllowlist) {
			continue
		}
		if snap.IsCommitted() {
			if _, ok := allowed[v]; ok {
				continue
			}
		}
		sigs := []string{"ld_preload_in_process_env", "target_process:" + comm}
		if suspiciousPath(v) {
			sigs = append(sigs, "preload_path_suspicious")
		}
		if !filepath.IsAbs(v) || strings.Contains(v, "./") {
			sigs = append(sigs, "non_absolute_preload")
		}
		conf, _ := rules.Score(pack, RuleProcLDPreload, sigs)
		ev := event.Event{
			SchemaVersion:   event.SchemaVersion,
			AgentVersion:    agentVer,
			Timestamp:       now,
			RuleID:          RuleProcLDPreload,
			RulePackVersion: pack.Version,
			TechniqueIDs:    []string{"T1574.006", "T1014"},
			Tactic:          "defense-evasion",
			Confidence:      conf,
			Severity:        rules.SeverityFromConfidence(conf, learning),
			Entity: event.Entity{
				Type: event.EntityProcess,
				ID:   strconv.Itoa(pid),
				Path: procfs.ResolveExe(pid),
			},
			Signals:      sigs,
			Evidence:     "LD_PRELOAD=" + truncate(v, 200),
			LearningOnly: learning || conf < cfg.MinConfidenceAlert,
		}
		ev.NormalizeDedup()
		events = append(events, ev)
	}
	return events, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func allLinesAllowlisted(content string, allow []string) bool {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !isAllowlistedValue(line, allow) {
			return false
		}
	}
	return true
}

func isAllowlistedValue(v string, allow []string) bool {
	for _, a := range allow {
		if a != "" && strings.Contains(v, a) {
			return true
		}
	}
	return false
}

func suspiciousPath(v string) bool {
	low := strings.ToLower(v)
	for _, s := range []string{"/tmp/", "/dev/shm/", "/var/tmp/", "/.cache/"} {
		if strings.Contains(low, s) {
			return true
		}
	}
	return strings.HasPrefix(low, ".")
}

// BuildBaselineLDPreload records current LD_PRELOAD values from target processes.
func BuildBaselineLDPreload(cfg *config.Config, snap *baseline.Snapshot) error {
	pids, err := procfs.Processes()
	if err != nil {
		return err
	}
	targets := map[string]struct{}{}
	for _, n := range cfg.TargetProcessNames {
		targets[strings.ToLower(n)] = struct{}{}
	}
	seen := map[string]struct{}{}
	for _, pid := range pids {
		comm, err := procfs.Comm(pid)
		if err != nil {
			continue
		}
		if _, ok := targets[strings.ToLower(strings.TrimSpace(comm))]; !ok {
			continue
		}
		env, err := procfs.Environ(pid)
		if err != nil {
			continue
		}
		v, ok := env["LD_PRELOAD"]
		if !ok || strings.TrimSpace(v) == "" {
			continue
		}
		seen[v] = struct{}{}
	}
	var vals []string
	for v := range seen {
		vals = append(vals, v)
	}
	snap.LDPreload = vals
	return nil
}
