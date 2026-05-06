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

const RuleShellRCPersistence = "SHELL_RC_PERSISTENCE"

// globalShellRC are system-wide shell init files. Any modification to these
// affects every interactive login and is therefore a high-value target.
var globalShellRC = []string{
	"/etc/profile",
	"/etc/bash.bashrc",
	"/etc/zshrc",
	"/etc/zsh/zshrc",
	"/etc/fish/config.fish",
}

// globalShellRCDirs hold drop-in files (profile.d style) that extend the
// global init set.
var globalShellRCDirs = []string{
	"/etc/profile.d",
	"/etc/zsh/zshrc.d",
	"/etc/fish/conf.d",
}

// userShellRCNames are the per-user filenames discovered in every homedir.
var userShellRCNames = []string{
	".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile",
	".kshrc", ".cshrc", ".tcshrc",
}

// sshRCNames are per-user SSH login hooks. ~/.ssh/rc runs for every SSH
// login and is a stealthy persistence vector (T1546.004-adjacent).
var sshRCNames = []string{".ssh/rc", ".ssh/environment"}

func collectShellRCTargets() []string {
	var out []string
	for _, f := range globalShellRC {
		if _, err := os.Stat(f); err == nil {
			out = append(out, f)
		}
	}
	for _, d := range globalShellRCDirs {
		out = append(out, walkFiles(d)...)
	}
	users, err := passwdUsers()
	if err != nil {
		return out
	}
	for _, u := range users {
		if u.dir == "" {
			continue
		}
		for _, name := range userShellRCNames {
			p := filepath.Join(u.dir, name)
			if _, err := os.Stat(p); err == nil {
				out = append(out, p)
			}
		}
		for _, name := range sshRCNames {
			p := filepath.Join(u.dir, name)
			if _, err := os.Stat(p); err == nil {
				out = append(out, p)
			}
		}
	}
	return out
}

// suspiciousShellRCTokens catches payloads commonly dropped into shell rc
// files by live-off-the-land adversaries.
var suspiciousShellRCTokens = []string{
	"curl ", "wget ", "base64 -d", "base64 --decode", "bash -i",
	"/dev/tcp/", "nohup ", "disown", "eval $(",
	"HISTFILE=/dev/null", "unset HISTFILE", "export HISTFILE=/dev/null",
	"alias sudo=", "alias ssh=",
}

func scanShellRC(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string, now time.Time) []event.Event {
	learning := cfg.LearningMode || !snap.IsCommitted()
	if cfg.FirstRunAllowAlerts {
		learning = cfg.LearningMode
	}
	var events []event.Event
	for _, path := range collectShellRCTargets() {
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
		low := strings.ToLower(string(data))
		suspicious := false
		for _, tok := range suspiciousShellRCTokens {
			if strings.Contains(low, strings.ToLower(tok)) {
				suspicious = true
				break
			}
		}
		if !changed && !suspicious {
			continue
		}
		var sigs []string
		if changed {
			sigs = append(sigs, "shell_rc_changed")
		}
		if suspicious {
			sigs = append(sigs, "shell_rc_suspicious_token")
		}
		conf, _ := rules.Score(pack, RuleShellRCPersistence, sigs)
		ev := event.Event{
			SchemaVersion:   event.SchemaVersion,
			AgentVersion:    agentVer,
			Timestamp:       now,
			RuleID:          RuleShellRCPersistence,
			RulePackVersion: pack.Version,
			TechniqueIDs:    []string{"T1546.004"},
			Tactic:          "persistence",
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

// BuildBaselineShellRC captures hashes for all interactive shell init files
// visible at commit time.
func BuildBaselineShellRC(snap *baseline.Snapshot) error {
	recordPersistenceBaseline(snap.PersistenceFiles, collectShellRCTargets())
	return nil
}
