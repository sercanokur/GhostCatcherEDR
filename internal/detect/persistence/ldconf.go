package persistence

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/rules"
)

const RuleLDConfPersistence = "LD_SO_CONF_CHANGED"

var ldConfFiles = []string{"/etc/ld.so.conf"}

const ldConfDir = "/etc/ld.so.conf.d"

// suspiciousLoaderPaths are directories that, when added to ld.so.conf
// include globs, effectively give an attacker a system-wide .so preload
// capability even without tripping LD_PRELOAD heuristics.
var suspiciousLoaderPaths = []string{
	"/tmp/", "/dev/shm/", "/var/tmp/", "/home/",
}

func collectLDConfTargets() []string {
	var out []string
	for _, f := range ldConfFiles {
		if _, err := os.Stat(f); err == nil {
			out = append(out, f)
		}
	}
	out = append(out, walkFiles(ldConfDir, ".conf")...)
	return out
}

func scanLDConf(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string, now time.Time) []event.Event {
	learning := cfg.LearningMode || !snap.IsCommitted()
	if cfg.FirstRunAllowAlerts {
		learning = cfg.LearningMode
	}
	var events []event.Event
	for _, path := range collectLDConfTargets() {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		hash := fileSHA(path)
		if hash == "" {
			continue
		}
		prev, inBase := snap.PersistenceFiles[path]
		changed := !inBase || prev != hash

		var flagged []string
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.HasPrefix(line, "include ") {
				continue
			}
			// absolute directory entries only; anything else is noise
			if !filepath.IsAbs(line) {
				continue
			}
			for _, s := range suspiciousLoaderPaths {
				if strings.HasPrefix(line, s) {
					flagged = append(flagged, line)
					break
				}
			}
		}
		var sigs []string
		if changed {
			sigs = append(sigs, "ld_so_conf_changed")
		}
		if len(flagged) > 0 {
			sigs = append(sigs, "ld_so_conf_world_writable_entry")
		}
		if len(sigs) == 0 {
			continue
		}
		conf, _ := rules.Score(pack, RuleLDConfPersistence, sigs)
		ev := event.Event{
			SchemaVersion:   event.SchemaVersion,
			AgentVersion:    agentVer,
			Timestamp:       now,
			RuleID:          RuleLDConfPersistence,
			RulePackVersion: pack.Version,
			TechniqueIDs:    []string{"T1574.006"},
			Tactic:          "defense-evasion",
			Confidence:      conf,
			Severity:        rules.SeverityFromConfidence(conf, learning),
			Entity:          event.Entity{Type: event.EntityFile, ID: hash, Path: path},
			Signals:         sigs,
			Evidence:        truncate(strings.Join(flagged, " | "), 300),
			LearningOnly:    learning || conf < cfg.MinConfidenceAlert,
		}
		ev.NormalizeDedup()
		events = append(events, ev)
	}
	return events
}

// BuildBaselineLDConf captures ld.so.conf.d hashes.
func BuildBaselineLDConf(snap *baseline.Snapshot) error {
	recordPersistenceBaseline(snap.PersistenceFiles, collectLDConfTargets())
	return nil
}
