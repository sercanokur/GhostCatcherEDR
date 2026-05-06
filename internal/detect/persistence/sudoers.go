package persistence

import (
	"bufio"
	"os"
	"strings"
	"time"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/rules"
)

const RuleSudoersPersistence = "SUDOERS_PERSISTENCE"

var sudoersTargets = []string{"/etc/sudoers"}

const sudoersDir = "/etc/sudoers.d"

// dangerousSudoersDirectives produce privileged command execution without
// authentication when they appear in a new/changed sudoers line. The agent
// deliberately ignores comments and the standard `Defaults` block.
var dangerousSudoersDirectives = []string{
	"NOPASSWD:", "!authenticate",
	" ALL=(ALL:ALL) ", " ALL=(ALL) ALL", " ALL=(root) ALL", " ALL=(ALL) NOPASSWD:",
}

func collectSudoersTargets() []string {
	var out []string
	for _, f := range sudoersTargets {
		if _, err := os.Stat(f); err == nil {
			out = append(out, f)
		}
	}
	out = append(out, walkFiles(sudoersDir)...)
	return out
}

func scanSudoers(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string, now time.Time) []event.Event {
	learning := cfg.LearningMode || !snap.IsCommitted()
	if cfg.FirstRunAllowAlerts {
		learning = cfg.LearningMode
	}
	var events []event.Event
	for _, path := range collectSudoersTargets() {
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

		sc := bufio.NewScanner(strings.NewReader(string(data)))
		var flagged []string
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Defaults") {
				continue
			}
			for _, d := range dangerousSudoersDirectives {
				if strings.Contains(line, d) {
					flagged = append(flagged, truncate(line, 180))
					break
				}
			}
		}

		var sigs []string
		if changed {
			sigs = append(sigs, "sudoers_changed")
		}
		if len(flagged) > 0 {
			sigs = append(sigs, "sudoers_nopasswd_or_unrestricted")
		}
		if len(sigs) == 0 {
			continue
		}
		conf, _ := rules.Score(pack, RuleSudoersPersistence, sigs)
		ev := event.Event{
			SchemaVersion:   event.SchemaVersion,
			AgentVersion:    agentVer,
			Timestamp:       now,
			RuleID:          RuleSudoersPersistence,
			RulePackVersion: pack.Version,
			TechniqueIDs:    []string{"T1548.003"},
			Tactic:          "privilege-escalation",
			Confidence:      conf,
			Severity:        rules.SeverityFromConfidence(conf, learning),
			Entity:          event.Entity{Type: event.EntityFile, ID: hash, Path: path},
			Signals:         sigs,
			Evidence:        truncate(strings.Join(flagged, " | "), 400),
			LearningOnly:    learning || conf < cfg.MinConfidenceAlert,
		}
		ev.NormalizeDedup()
		events = append(events, ev)
	}
	return events
}

// BuildBaselineSudoers captures sudoers hashes.
func BuildBaselineSudoers(snap *baseline.Snapshot) error {
	recordPersistenceBaseline(snap.PersistenceFiles, collectSudoersTargets())
	return nil
}
