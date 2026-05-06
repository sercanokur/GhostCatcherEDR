package persistence

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/rules"
)

const RuleSystemdPersistence = "SYSTEMD_PERSISTENCE"

// systemdUnitDirs are every canonical location a systemd .service or
// .timer can live on a modern Linux host. User-scoped dirs are included so
// a non-root foothold that writes under ~/.config/systemd/user/ is visible
// when the agent runs as root.
var systemdUnitDirs = []string{
	"/etc/systemd/system",
	"/etc/systemd/system/multi-user.target.wants",
	"/etc/systemd/system/default.target.wants",
	"/lib/systemd/system",
	"/usr/lib/systemd/system",
	"/run/systemd/system",
	"/run/systemd/generator",
	"/run/systemd/generator.late",
}

// highRiskSystemdDirectives lists directives that, when their value contains
// a shell/downloader, produce a near-certain persistence red flag.
var highRiskSystemdDirectives = []string{
	"ExecStart=", "ExecStartPre=", "ExecStartPost=",
	"ExecReload=", "ExecStop=", "ExecStopPost=",
}

// scanSystemdUnits walks every known unit directory and emits events for
// units that are either (a) new vs baseline, (b) changed content, or
// (c) contain high-risk Exec* directives coupled with User=root.
func scanSystemdUnits(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string, now time.Time) ([]event.Event, error) {
	learning := cfg.LearningMode || !snap.IsCommitted()
	if cfg.FirstRunAllowAlerts {
		learning = cfg.LearningMode
	}
	var events []event.Event
	for _, dir := range systemdUnitDirs {
		for _, path := range walkFiles(dir, ".service", ".timer", ".socket", ".path") {
			ev, ok := evaluateSystemdUnit(path, cfg, snap, pack, agentVer, now, learning)
			if ok {
				events = append(events, ev)
			}
		}
	}
	return events, nil
}

func evaluateSystemdUnit(path string, cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string, now time.Time, learning bool) (event.Event, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return event.Event{}, false
	}
	hash := fileSHA(path)
	if hash == "" {
		return event.Event{}, false
	}
	prev, inBase := snap.PersistenceFiles[path]
	newOrChanged := !inBase || prev != hash

	content := string(data)
	low := strings.ToLower(content)

	var sigs []string
	if newOrChanged {
		sigs = append(sigs, "systemd_unit_new_or_changed")
	}
	if containsAnyDirective(content, highRiskSystemdDirectives) {
		if strings.Contains(low, "curl ") || strings.Contains(low, "wget ") ||
			strings.Contains(low, "bash -c") || strings.Contains(low, "/tmp/") ||
			strings.Contains(low, "/dev/shm/") || strings.Contains(low, "base64 -d") ||
			strings.Contains(low, "/dev/tcp/") {
			sigs = append(sigs, "exec_directive_suspicious_payload")
		}
	}
	if strings.Contains(low, "user=root") && (strings.Contains(low, "/tmp/") || strings.Contains(low, "/dev/shm/")) {
		sigs = append(sigs, "root_execution_from_world_writable")
	}
	if filepath.Ext(strings.ToLower(path)) == ".timer" && newOrChanged {
		sigs = append(sigs, "new_systemd_timer")
	}
	if len(sigs) == 0 || (!newOrChanged && !containsSuspiciousPayload(sigs)) {
		return event.Event{}, false
	}
	conf, _ := rules.Score(pack, RuleSystemdPersistence, sigs)
	ev := event.Event{
		SchemaVersion:   event.SchemaVersion,
		AgentVersion:    agentVer,
		Timestamp:       now,
		RuleID:          RuleSystemdPersistence,
		RulePackVersion: pack.Version,
		TechniqueIDs:    []string{"T1053.006", "T1543.002"},
		Tactic:          "persistence",
		Confidence:      conf,
		Severity:        rules.SeverityFromConfidence(conf, learning),
		Entity:          event.Entity{Type: event.EntityFile, ID: hash, Path: path},
		Signals:         sigs,
		Evidence:        truncate(firstMatchingLine(content, highRiskSystemdDirectives), 300),
		LearningOnly:    learning || conf < cfg.MinConfidenceAlert,
	}
	ev.NormalizeDedup()
	return ev, true
}

func containsSuspiciousPayload(sigs []string) bool {
	for _, s := range sigs {
		if s == "exec_directive_suspicious_payload" || s == "root_execution_from_world_writable" {
			return true
		}
	}
	return false
}

func containsAnyDirective(content string, directives []string) bool {
	for _, d := range directives {
		if strings.Contains(content, d) {
			return true
		}
	}
	return false
}

func firstMatchingLine(content string, needles []string) string {
	for _, line := range strings.Split(content, "\n") {
		for _, n := range needles {
			if strings.Contains(line, n) {
				return strings.TrimSpace(line)
			}
		}
	}
	return ""
}

// BuildBaselineSystemd captures hashes for every unit file currently present
// under the canonical unit directories. Deltas trigger SYSTEMD_PERSISTENCE.
func BuildBaselineSystemd(snap *baseline.Snapshot) error {
	for _, dir := range systemdUnitDirs {
		paths := walkFiles(dir, ".service", ".timer", ".socket", ".path")
		recordPersistenceBaseline(snap.PersistenceFiles, paths)
	}
	return nil
}
