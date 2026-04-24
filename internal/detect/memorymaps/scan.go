package memorymaps

import (
	"strconv"
	"strings"
	"time"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/procfs"
	"ghostcatcher/internal/rules"
)

const RuleProcRWX = "PROC_RWX_MEMORY_SEGMENT"

// Scan inspects /proc/[pid]/maps for rwx mappings on configured server processes (in-memory / JIT shellcode indicators).
func Scan(cfg *config.Config, _ *baseline.Snapshot, pack *rules.Pack, agentVer string) ([]event.Event, error) {
	if !cfg.MapsScanEnabled {
		return nil, nil
	}
	var events []event.Event
	now := time.Now().UTC()
	want := map[string]struct{}{}
	for _, n := range cfg.MapsWatchProcesses {
		want[strings.ToLower(strings.TrimSpace(n))] = struct{}{}
	}
	pids, err := procfs.Processes()
	if err != nil {
		return nil, err
	}
	for _, pid := range pids {
		comm, err := procfs.Comm(pid)
		if err != nil {
			continue
		}
		if _, ok := want[strings.ToLower(strings.TrimSpace(comm))]; !ok {
			continue
		}
		entries, err := procfs.ReadMaps(pid)
		if err != nil {
			continue
		}
		ok, pathHint := procfs.HasRWXSegment(entries)
		if !ok {
			continue
		}
		if pathAllowlisted(pathHint, cfg.MapsPathAllowlist) {
			continue
		}
		sigs := []string{"rwx_memory_mapping", "comm:" + comm}
		if pathHint != "" {
			sigs = append(sigs, "mapping_path:"+truncate(pathHint, 80))
		} else {
			sigs = append(sigs, "anonymous_rwx_mapping")
		}
		conf, _ := rules.Score(pack, RuleProcRWX, sigs)
		if conf < 80 {
			conf = 80
		}
		ev := event.Event{
			SchemaVersion:   event.SchemaVersion,
			AgentVersion:    agentVer,
			Timestamp:       now,
			RuleID:          RuleProcRWX,
			RulePackVersion: pack.Version,
			TechniqueIDs:    []string{"T1055", "T1505.003"},
			Tactic:          "defense-evasion",
			Confidence:      conf,
			Severity:        rules.SeverityFromConfidence(conf, false),
			Entity: event.Entity{
				Type: event.EntityProcess,
				ID:   strconv.Itoa(pid),
				Path: procfs.ResolveExe(pid),
			},
			Signals:      sigs,
			Evidence:     "pid=" + strconv.Itoa(pid) + " comm=" + comm + " map=" + truncate(pathHint, 120),
			LearningOnly: false,
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

func pathAllowlisted(path string, prefixes []string) bool {
	if path == "" {
		return false
	}
	low := strings.ToLower(path)
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(low, strings.ToLower(p)) {
			return true
		}
	}
	return false
}
