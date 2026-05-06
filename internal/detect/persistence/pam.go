package persistence

import (
	"os"
	"strings"
	"time"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/rules"
)

const RulePAMPersistence = "PAM_PERSISTENCE"

// pamConfigDir holds PAM service definitions; a rogue rule that adds
// `pam_exec.so` or a rogue `.so` path-based module is a common backdoor.
const pamConfigDir = "/etc/pam.d"

// pamModuleDirs are the standard locations distro maintainers ship PAM
// .so modules from. Any unknown .so appearing in these dirs is suspicious.
var pamModuleDirs = []string{
	"/lib/x86_64-linux-gnu/security",
	"/lib64/security",
	"/lib/security",
	"/usr/lib/security",
	"/usr/lib64/security",
	"/usr/lib/x86_64-linux-gnu/security",
}

// suspiciousPAMTokens flags rogue module references inside /etc/pam.d files.
// `pam_exec.so` in a new auth/account stanza is a classic backdoor primitive.
var suspiciousPAMTokens = []string{
	"pam_exec.so", "pam_python.so", "pam_succeed_if.so",
	"/tmp/", "/dev/shm/", "/home/",
}

func collectPAMTargets() []string {
	var out []string
	out = append(out, walkFiles(pamConfigDir)...)
	for _, d := range pamModuleDirs {
		out = append(out, walkFiles(d, ".so")...)
	}
	return out
}

func scanPAM(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string, now time.Time) []event.Event {
	learning := cfg.LearningMode || !snap.IsCommitted()
	if cfg.FirstRunAllowAlerts {
		learning = cfg.LearningMode
	}
	var events []event.Event
	for _, path := range collectPAMTargets() {
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

		isConfig := strings.HasPrefix(path, pamConfigDir+"/")
		var sigs []string
		if changed {
			if isConfig {
				sigs = append(sigs, "pam_config_changed")
			} else {
				sigs = append(sigs, "pam_module_new_or_changed")
			}
		}
		if isConfig {
			low := strings.ToLower(string(data))
			for _, tok := range suspiciousPAMTokens {
				if strings.Contains(low, tok) && changed {
					sigs = append(sigs, "pam_suspicious_reference:"+tok)
					break
				}
			}
		}
		if len(sigs) == 0 {
			continue
		}
		conf, _ := rules.Score(pack, RulePAMPersistence, sigs)
		ev := event.Event{
			SchemaVersion:   event.SchemaVersion,
			AgentVersion:    agentVer,
			Timestamp:       now,
			RuleID:          RulePAMPersistence,
			RulePackVersion: pack.Version,
			TechniqueIDs:    []string{"T1556.003"},
			Tactic:          "credential-access",
			Confidence:      conf,
			Severity:        rules.SeverityFromConfidence(conf, learning),
			Entity:          event.Entity{Type: event.EntityFile, ID: hash, Path: path},
			Signals:         sigs,
			Evidence:        truncate(strings.TrimSpace(string(data)), 300),
			LearningOnly:    learning || conf < cfg.MinConfidenceAlert,
		}
		ev.NormalizeDedup()
		events = append(events, ev)
	}
	return events
}

// BuildBaselinePAM captures PAM config + module hashes.
func BuildBaselinePAM(snap *baseline.Snapshot) error {
	recordPersistenceBaseline(snap.PersistenceFiles, collectPAMTargets())
	return nil
}
