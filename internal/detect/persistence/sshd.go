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

const RuleSSHDConfig = "SSHD_CONFIG_ANOMALY"

var sshdFiles = []string{"/etc/ssh/sshd_config"}

const sshdDropinDir = "/etc/ssh/sshd_config.d"

// riskySSHDDirectives are directives that, when changed from distro default
// to a non-default value, usually mean someone weakened SSH for persistence.
var riskySSHDDirectives = []string{
	"PermitRootLogin", "PasswordAuthentication", "ChallengeResponseAuthentication",
	"AuthorizedKeysCommand", "AuthorizedKeysCommandUser",
	"ForceCommand", "GatewayPorts", "AllowTcpForwarding",
	"PermitTunnel", "PermitUserEnvironment", "Match User",
}

func collectSSHDTargets() []string {
	var out []string
	for _, f := range sshdFiles {
		if _, err := os.Stat(f); err == nil {
			out = append(out, f)
		}
	}
	out = append(out, walkFiles(sshdDropinDir, ".conf")...)
	return out
}

func scanSSHD(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string, now time.Time) []event.Event {
	learning := cfg.LearningMode || !snap.IsCommitted()
	if cfg.FirstRunAllowAlerts {
		learning = cfg.LearningMode
	}
	var events []event.Event
	for _, path := range collectSSHDTargets() {
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
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			for _, d := range riskySSHDDirectives {
				if strings.HasPrefix(line, d) || strings.HasPrefix(line, strings.ToLower(d)) {
					flagged = append(flagged, truncate(line, 200))
					break
				}
			}
		}
		var sigs []string
		if changed {
			sigs = append(sigs, "sshd_config_changed")
		}
		for _, l := range flagged {
			low := strings.ToLower(l)
			if strings.Contains(low, "authorizedkeyscommand") ||
				strings.Contains(low, "forcecommand") ||
				strings.Contains(low, "permitrootlogin yes") ||
				strings.Contains(low, "passwordauthentication yes") {
				sigs = append(sigs, "sshd_high_risk_directive")
				break
			}
		}
		if len(sigs) == 0 {
			continue
		}
		conf, _ := rules.Score(pack, RuleSSHDConfig, sigs)
		ev := event.Event{
			SchemaVersion:   event.SchemaVersion,
			AgentVersion:    agentVer,
			Timestamp:       now,
			RuleID:          RuleSSHDConfig,
			RulePackVersion: pack.Version,
			TechniqueIDs:    []string{"T1098.004", "T1556"},
			Tactic:          "persistence",
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

// BuildBaselineSSHD captures sshd config hashes.
func BuildBaselineSSHD(snap *baseline.Snapshot) error {
	recordPersistenceBaseline(snap.PersistenceFiles, collectSSHDTargets())
	return nil
}
