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

const (
	RuleUserPersistence   = "USER_ACCOUNT_ANOMALY"
	RuleUserShellEnabled  = "USER_SHELL_ENABLED"
	RuleUserPasswdHash    = "USER_PASSWD_HASH_CHANGE"
)

var userFiles = []string{"/etc/passwd", "/etc/shadow"}

// scanUsers flags three distinct account-level persistence primitives:
//  1. Any non-root UID 0 account (classic privileged backdoor).
//  2. New accounts vs baseline that have a login shell.
//  3. Shadow entries with empty password hash ("!" / "*" are allowed; "" is not).
func scanUsers(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string, now time.Time) []event.Event {
	learning := cfg.LearningMode || !snap.IsCommitted()
	if cfg.FirstRunAllowAlerts {
		learning = cfg.LearningMode
	}
	var events []event.Event

	events = append(events, detectUIDZero(cfg, snap, pack, agentVer, now, learning)...)
	for _, path := range userFiles {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		hash := fileSHA(path)
		if hash == "" {
			continue
		}
		prev, inBase := snap.PersistenceFiles[path]
		if inBase && prev == hash {
			continue
		}
		sigs := []string{"user_db_changed:" + path}
		ruleID := RuleUserPersistence
		if path == "/etc/shadow" {
			if emptyPasswordLine := findEmptyShadowHash(path); emptyPasswordLine != "" {
				sigs = append(sigs, "empty_password_hash")
			}
			ruleID = RuleUserPasswdHash
			sigs = append(sigs, "user_passwd_hash_change")
		}
		if path == "/etc/passwd" {
			if shells := findEnabledServiceShells(path); len(shells) > 0 {
				sigs = append(sigs, "user_shell_enabled:"+strings.Join(shells, ","))
				ruleID = RuleUserShellEnabled
			}
		}
		conf, _ := rules.Score(pack, ruleID, sigs)
		ev := event.Event{
			SchemaVersion:   event.SchemaVersion,
			AgentVersion:    agentVer,
			Timestamp:       now,
			RuleID:          ruleID,
			RulePackVersion: pack.Version,
			TechniqueIDs:    []string{"T1136.001"},
			Tactic:          "persistence",
			Confidence:      conf,
			Severity:        rules.SeverityFromConfidence(conf, learning),
			Entity:          event.Entity{Type: event.EntityFile, ID: hash, Path: path},
			Signals:         sigs,
			Evidence:        "file hash changed since baseline",
			LearningOnly:    learning || conf < cfg.MinConfidenceAlert,
			Src:             event.SrcFIM,
			Type:            event.TypeDelta,
		}
		ev.NormalizeDedup()
		events = append(events, ev)
	}
	return events
}

func detectUIDZero(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string, now time.Time, learning bool) []event.Event {
	users, err := passwdUsers()
	if err != nil {
		return nil
	}
	var events []event.Event
	for _, u := range users {
		if u.uid != "0" || u.name == "root" {
			continue
		}
		sigs := []string{"non_root_uid_zero_account:" + u.name}
		conf, _ := rules.Score(pack, RuleUserPersistence, sigs)
		if conf < 95 {
			conf = 95
		}
		ev := event.Event{
			SchemaVersion:   event.SchemaVersion,
			AgentVersion:    agentVer,
			Timestamp:       now,
			RuleID:          RuleUserPersistence,
			RulePackVersion: pack.Version,
			TechniqueIDs:    []string{"T1136.001", "T1078.003"},
			Tactic:          "persistence",
			Confidence:      conf,
			Severity:        rules.SeverityFromConfidence(conf, false),
			Entity:          event.Entity{Type: event.EntityUser, ID: u.name, User: u.name},
			Signals:         sigs,
			Evidence:        "duplicate UID 0 account: " + u.name,
			LearningOnly:    false,
		}
		ev.NormalizeDedup()
		events = append(events, ev)
	}
	return events
}

func findEmptyShadowHash(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := sc.Text()
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 2 {
			continue
		}
		if parts[1] == "" {
			return line
		}
	}
	return ""
}

// findEnabledServiceShells returns service-like accounts whose shell is no
// longer nologin/false (bhv USER_SHELL_ENABLED).
func findEnabledServiceShells(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 7 {
			continue
		}
		name, shell := parts[0], parts[6]
		if name == "root" || name == "sync" || name == "shutdown" || name == "halt" {
			continue
		}
		// Heuristic service accounts: system UIDs or names ending in daemon-ish patterns.
		uid := parts[2]
		if uid == "0" {
			continue
		}
		if shell == "/usr/sbin/nologin" || shell == "/bin/false" || shell == "/sbin/nologin" || shell == "" {
			continue
		}
		// Only flag typical service account name patterns / low UIDs.
		if uid < "1000" || strings.HasSuffix(name, "d") || strings.Contains(name, "www") ||
			strings.Contains(name, "nginx") || strings.Contains(name, "mysql") {
			out = append(out, name+":"+shell)
		}
	}
	return out
}

// BuildBaselineUsers snapshots /etc/passwd and /etc/shadow hashes.
func BuildBaselineUsers(snap *baseline.Snapshot) error {
	recordPersistenceBaseline(snap.PersistenceFiles, userFiles)
	return nil
}
