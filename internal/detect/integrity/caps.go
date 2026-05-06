package integrity

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/rules"
)

// capsScanDirs limits the xattr walk to dirs where setcap-granted binaries
// conventionally live. Arbitrary filesystem coverage is too expensive; the
// plan is to pair this with a runtime /proc scan in phase 3.
var capsScanDirs = []string{
	"/bin", "/sbin", "/usr/bin", "/usr/sbin",
	"/usr/local/bin", "/usr/local/sbin",
}

// scanCapabilities diffs the current `security.capability` xattr map against
// the baseline. On platforms without xattr support (e.g. darwin dev hosts)
// readFileCapability returns "" for every path and the scan emits no events.
func scanCapabilities(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string, now time.Time) []event.Event {
	learning := cfg.LearningMode || !snap.IsCommitted()
	if cfg.FirstRunAllowAlerts {
		learning = cfg.LearningMode
	}
	current := enumerateCapabilities()
	base := snap.FileCapabilities
	if base == nil {
		base = map[string]string{}
	}
	var events []event.Event
	for path, cap := range current {
		prev, ok := base[path]
		if ok && prev == cap {
			continue
		}
		sigs := []string{"file_capability_present"}
		if !ok {
			sigs = append(sigs, "new_file_capability")
		} else {
			sigs = append(sigs, "file_capability_changed")
		}
		conf, _ := rules.Score(pack, RuleCapabilityAnomaly, sigs)
		if contains(sigs, "new_file_capability") && conf < 85 {
			conf = 85
		}
		ev := event.Event{
			SchemaVersion:   event.SchemaVersion,
			AgentVersion:    agentVer,
			Timestamp:       now,
			RuleID:          RuleCapabilityAnomaly,
			RulePackVersion: pack.Version,
			TechniqueIDs:    []string{"T1548.001"},
			Tactic:          "privilege-escalation",
			Confidence:      conf,
			Severity:        rules.SeverityFromConfidence(conf, learning),
			Entity:          event.Entity{Type: event.EntityFile, ID: cap, Path: path},
			Signals:         sigs,
			Evidence:        fmt.Sprintf("path=%s cap=%s", path, cap),
			LearningOnly:    learning || conf < cfg.MinConfidenceAlert,
		}
		ev.NormalizeDedup()
		events = append(events, ev)
	}
	return events
}

func enumerateCapabilities() map[string]string {
	out := map[string]string{}
	for _, dir := range capsScanDirs {
		st, err := os.Stat(dir)
		if err != nil || !st.IsDir() {
			continue
		}
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			cap := readFileCapability(path)
			if cap != "" {
				out[path] = cap
			}
			return nil
		})
	}
	return out
}

// BuildBaselineCapabilities freezes the current file-capability map.
func BuildBaselineCapabilities(_ *config.Config, snap *baseline.Snapshot) error {
	snap.FileCapabilities = enumerateCapabilities()
	return nil
}
