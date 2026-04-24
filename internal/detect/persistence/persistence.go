package persistence

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/rules"

	"golang.org/x/crypto/ssh"
)

const (
	RuleAuthKeyNew     = "SSH_AUTHKEY_NEW"
	RuleAuthKeyAnomaly = "SSH_AUTHKEY_INVALID_LINE"
	RuleCronHighRisk   = "CRON_HIGH_RISK"
)

func Scan(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string) ([]event.Event, error) {
	var out []event.Event
	now := time.Now().UTC()

	keys, err := scanAuthorizedKeys(cfg, snap, pack, agentVer, now)
	if err != nil {
		return nil, err
	}
	out = append(out, keys...)

	crons, err := scanCron(cfg, snap, pack, agentVer, now)
	if err != nil {
		return nil, err
	}
	out = append(out, crons...)

	return out, nil
}

func scanAuthorizedKeys(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string, now time.Time) ([]event.Event, error) {
	var events []event.Event
	users, err := passwdUsers()
	if err != nil {
		return nil, err
	}
	learning := cfg.LearningMode || !snap.IsCommitted()
	if cfg.FirstRunAllowAlerts {
		learning = cfg.LearningMode
	}

	for _, u := range users {
		if u.dir == "" || u.shell == "/usr/sbin/nologin" || u.shell == "/bin/false" {
			continue
		}
		p := filepath.Join(u.dir, ".ssh", "authorized_keys")
		if _, err := os.Stat(p); err != nil {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		baselineFPs := map[string]struct{}{}
		if fps, ok := snap.AuthKeys[p]; ok {
			for _, fp := range fps {
				baselineFPs[fp] = struct{}{}
			}
		}
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		lineNo := 0
		for sc.Scan() {
			lineNo++
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
			if err != nil {
				conf, _ := rules.Score(pack, RuleAuthKeyAnomaly, []string{"invalid_openssh_line"})
				ev := event.Event{
					SchemaVersion:   event.SchemaVersion,
					AgentVersion:    agentVer,
					Timestamp:       now,
					RuleID:          RuleAuthKeyAnomaly,
					RulePackVersion: pack.Version,
					TechniqueIDs:    []string{"T1098.004"},
					Tactic:          "persistence",
					Confidence:      conf,
					Severity:        rules.SeverityFromConfidence(conf, learning),
					Entity: event.Entity{
						Type: event.EntityUser,
						ID:   u.name,
						Path: p,
						User: u.name,
					},
					Signals:      []string{"invalid_openssh_line"},
					Evidence:     truncate(line, 120),
					LearningOnly: learning || conf < cfg.MinConfidenceAlert,
				}
				ev.NormalizeDedup()
				events = append(events, ev)
				continue
			}
			fp := ssh.FingerprintSHA256(pub)
			if _, ok := baselineFPs[fp]; ok {
				continue
			}
			sigs := []string{"new_authorized_key_fingerprint"}
			if u.name == "root" || inSudoGroup(u.name) {
				sigs = append(sigs, "privileged_user")
			}
			conf, _ := rules.Score(pack, RuleAuthKeyNew, sigs)
			ev := event.Event{
				SchemaVersion:   event.SchemaVersion,
				AgentVersion:    agentVer,
				Timestamp:       now,
				RuleID:          RuleAuthKeyNew,
				RulePackVersion: pack.Version,
				TechniqueIDs:    []string{"T1098.004"},
				Tactic:          "persistence",
				Confidence:      conf,
				Severity:        rules.SeverityFromConfidence(conf, learning),
				Entity: event.Entity{
					Type: event.EntityUser,
					ID:   u.name + ":" + fp,
					Path: p,
					User: u.name,
				},
				Signals:      sigs,
				Evidence:     fmt.Sprintf("fingerprint:%s line:%d", fp, lineNo),
				LearningOnly: learning || conf < cfg.MinConfidenceAlert,
			}
			ev.NormalizeDedup()
			events = append(events, ev)
		}
	}
	return events, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

type passwdEntry struct {
	name, dir, shell string
}

func passwdUsers() ([]passwdEntry, error) {
	out, err := exec.Command("getent", "passwd").Output()
	if err != nil {
		var fallback []passwdEntry
		if u, e := user.Current(); e == nil {
			fallback = append(fallback, passwdEntry{name: u.Username, dir: u.HomeDir})
		}
		return fallback, nil
	}
	var res []passwdEntry
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		p := strings.Split(line, ":")
		if len(p) < 7 {
			continue
		}
		res = append(res, passwdEntry{name: p[0], dir: p[5], shell: p[6]})
	}
	return res, nil
}

func inSudoGroup(username string) bool {
	out, err := exec.Command("id", "-nG", username).Output()
	if err != nil {
		return false
	}
	groups := strings.Fields(string(out))
	for _, g := range groups {
		if g == "sudo" || g == "wheel" || g == "admin" {
			return true
		}
	}
	return false
}

var cronRiskPatterns = []string{
	"curl ", "wget ", "bash -c", "/bin/bash -c", "base64 -d", "python -c", "perl -e",
	"/dev/tcp", "eval ", "| bash", "|sh ", "chmod +x", "openssl ",
}

func scanCron(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string, now time.Time) ([]event.Event, error) {
	var events []event.Event
	learning := cfg.LearningMode || !snap.IsCommitted()
	if cfg.FirstRunAllowAlerts {
		learning = cfg.LearningMode
	}

	files := []string{"/etc/crontab"}
	if ents, err := os.ReadDir("/etc/cron.d"); err == nil {
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			files = append(files, filepath.Join("/etc/cron.d", e.Name()))
		}
	}
	if ents, err := os.ReadDir("/var/spool/cron/crontabs"); err == nil {
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			files = append(files, filepath.Join("/var/spool/cron/crontabs", e.Name()))
		}
	}

	for _, fpath := range files {
		st, err := os.Stat(fpath)
		if err != nil {
			continue
		}
		_ = st
		data, err := os.ReadFile(fpath)
		if err != nil {
			continue
		}
		baselineSet := map[string]struct{}{}
		for _, fp := range snap.CronLines[fpath] {
			baselineSet[fp] = struct{}{}
		}
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		lineNo := 0
		for sc.Scan() {
			lineNo++
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fp := cronLineFingerprint(fpath, line)
			if _, ok := baselineSet[fp]; ok {
				continue
			}
			risk := false
			low := strings.ToLower(line)
			for _, p := range cronRiskPatterns {
				if strings.Contains(low, strings.ToLower(p)) {
					risk = true
					break
				}
			}
			if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
				risk = true
			}
			sigs := []string{"new_cron_line"}
			if !risk {
				conf, _ := rules.Score(pack, RuleCronHighRisk, sigs)
				ev := event.Event{
					SchemaVersion:   event.SchemaVersion,
					AgentVersion:    agentVer,
					Timestamp:       now,
					RuleID:          RuleCronHighRisk,
					RulePackVersion: pack.Version,
					TechniqueIDs:    []string{"T1053.003"},
					Tactic:          "persistence",
					Confidence:      min(conf, 40),
					Severity:        event.SeverityInfo,
					Entity:          event.Entity{Type: event.EntityCron, ID: fp, Path: fpath},
					Signals:         sigs,
					Evidence:        truncate(line, 200),
					LearningOnly:    true,
				}
				ev.NormalizeDedup()
				events = append(events, ev)
				continue
			}
			sigs = append(sigs, "high_risk_token")
			conf, _ := rules.Score(pack, RuleCronHighRisk, sigs)
			ev := event.Event{
				SchemaVersion:   event.SchemaVersion,
				AgentVersion:    agentVer,
				Timestamp:       now,
				RuleID:          RuleCronHighRisk,
				RulePackVersion: pack.Version,
				TechniqueIDs:    []string{"T1053.003"},
				Tactic:          "persistence",
				Confidence:      conf,
				Severity:        rules.SeverityFromConfidence(conf, learning),
				Entity:          event.Entity{Type: event.EntityCron, ID: fp, Path: fpath},
				Signals:         sigs,
				Evidence:        truncate(line, 200),
				LearningOnly:    learning || conf < cfg.MinConfidenceAlert,
			}
			ev.NormalizeDedup()
			events = append(events, ev)
		}
	}
	return events, nil
}

func cronLineFingerprint(path, line string) string {
	h := sha256.Sum256([]byte(path + "\x00" + line))
	return hex.EncodeToString(h[:])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// BuildBaselineAuthKeys refreshes snapshot authorized_keys from disk (for commit).
func BuildBaselineAuthKeys(snap *baseline.Snapshot) error {
	users, err := passwdUsers()
	if err != nil {
		return err
	}
	for _, u := range users {
		if u.dir == "" {
			continue
		}
		p := filepath.Join(u.dir, ".ssh", "authorized_keys")
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var fps []string
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
			if err != nil {
				continue
			}
			fps = append(fps, ssh.FingerprintSHA256(pub))
		}
		if len(fps) > 0 {
			snap.AuthKeys[p] = fps
		}
	}
	return nil
}

// BuildBaselineCron captures all current cron lines into snapshot.
func BuildBaselineCron(snap *baseline.Snapshot) error {
	files := []string{"/etc/crontab"}
	if ents, err := os.ReadDir("/etc/cron.d"); err == nil {
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			files = append(files, filepath.Join("/etc/cron.d", e.Name()))
		}
	}
	if ents, err := os.ReadDir("/var/spool/cron/crontabs"); err == nil {
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			files = append(files, filepath.Join("/var/spool/cron/crontabs", e.Name()))
		}
	}
	for _, fpath := range files {
		data, err := os.ReadFile(fpath)
		if err != nil {
			continue
		}
		var fps []string
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fps = append(fps, cronLineFingerprint(fpath, line))
		}
		if len(fps) > 0 {
			snap.CronLines[fpath] = fps
		}
	}
	return nil
}
