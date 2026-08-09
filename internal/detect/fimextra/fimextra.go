// Package fimextra emits bhv.md FIM/INVENTORY DELTA nanos for Ubuntu
// persistence and defense-weakening paths not covered by the core
// persistence scanners.
package fimextra

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/rules"
)

// pathRule maps a filesystem glob/prefix to a nano ID.
type pathRule struct {
	ruleID string
	paths  []string // exact files or directories (walked one level)
	match  func(name, full string) bool
	signal string
}

var ruleset = []pathRule{
	{ruleID: "SSHD_DROPIN_NEW", paths: []string{"/etc/ssh/sshd_config.d"}, signal: "sshd_dropin",
		match: func(name, _ string) bool { return strings.HasSuffix(name, ".conf") }},
	{ruleID: "SSH_RC_HOOK", paths: []string{"/etc/ssh/sshrc"}, signal: "ssh_rc_hook",
		match: func(_, _ string) bool { return true }},
	{ruleID: "SSH_SOCKET_OVERRIDE", paths: []string{"/etc/systemd/system/ssh.socket.d", "/etc/systemd/system/ssh.service.d"}, signal: "ssh_socket_override",
		match: func(name, _ string) bool { return strings.HasSuffix(name, ".conf") }},
	{ruleID: "SSH_HOSTKEY_CHANGE", paths: []string{"/etc/ssh"}, signal: "ssh_hostkey_change",
		match: func(name, _ string) bool {
			return strings.HasPrefix(name, "ssh_host_") && !strings.HasSuffix(name, ".pub")
		}},
	{ruleID: "CRON_DROPIN_NEW", paths: []string{"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/etc/crontab"}, signal: "cron_dropin",
		match: func(_, _ string) bool { return true }},
	{ruleID: "CRON_SPOOL_CHANGE", paths: []string{"/var/spool/cron/crontabs"}, signal: "cron_spool",
		match: func(_, _ string) bool { return true }},
	{ruleID: "AT_JOB_NEW", paths: []string{"/var/spool/cron/atjobs"}, signal: "at_job",
		match: func(_, _ string) bool { return true }},
	{ruleID: "SYSTEMD_GENERATOR_NEW", paths: []string{"/etc/systemd/system-generators", "/usr/lib/systemd/system-generators"}, signal: "systemd_generator",
		match: func(_, _ string) bool { return true }},
	{ruleID: "SYSTEMD_DROPIN_OVERRIDE", paths: []string{"/etc/systemd/system"}, signal: "systemd_dropin",
		match: func(name, full string) bool {
			return strings.Contains(full, ".d/") && strings.HasSuffix(name, ".conf")
		}},
	{ruleID: "SYSTEMD_USER_PERSISTENCE", paths: []string{}, signal: "systemd_user",
		match: nil}, // handled specially
	{ruleID: "PAM_CONFIG_PROFILE_NEW", paths: []string{"/usr/share/pam-configs"}, signal: "pam_config_profile",
		match: func(_, _ string) bool { return true }},
	{ruleID: "NSS_CONFIG_CHANGE", paths: []string{"/etc/nsswitch.conf"}, signal: "nsswitch_change",
		match: func(_, _ string) bool { return true }},
	{ruleID: "APT_HOOK_PERSISTENCE", paths: []string{"/etc/apt/apt.conf.d"}, signal: "apt_hook",
		match: func(_, full string) bool {
			b, err := os.ReadFile(full)
			if err != nil {
				return false
			}
			s := string(b)
			return strings.Contains(s, "Pre-Invoke") || strings.Contains(s, "Post-Invoke")
		}},
	{ruleID: "MOTD_SCRIPT_NEW", paths: []string{"/etc/update-motd.d"}, signal: "motd_script",
		match: func(_, _ string) bool { return true }},
	{ruleID: "ENVIRONMENT_FILE_CHANGE", paths: []string{"/etc/environment", "/etc/default"}, signal: "environment_file",
		match: func(_, _ string) bool { return true }},
	{ruleID: "NETWORK_DISPATCHER_HOOK", paths: []string{
		"/etc/networkd-dispatcher", "/etc/NetworkManager/dispatcher.d", "/etc/network/if-up.d",
	}, signal: "network_dispatcher", match: func(_, _ string) bool { return true }},
	{ruleID: "UDEV_RUN_RULE", paths: []string{"/etc/udev/rules.d"}, signal: "udev_run",
		match: func(_, full string) bool {
			b, err := os.ReadFile(full)
			if err != nil {
				return false
			}
			return strings.Contains(string(b), "RUN+=")
		}},
	{ruleID: "POLKIT_RULE_NEW", paths: []string{"/etc/polkit-1/rules.d"}, signal: "polkit_rule",
		match: func(name, _ string) bool { return strings.HasSuffix(name, ".rules") }},
	{ruleID: "NEEDRESTART_HOOK", paths: []string{"/etc/needrestart/conf.d"}, signal: "needrestart_hook",
		match: func(_, _ string) bool { return true }},
	{ruleID: "RC_LOCAL_REVIVED", paths: []string{"/etc/rc.local"}, signal: "rc_local",
		match: func(_, full string) bool {
			st, err := os.Stat(full)
			return err == nil && st.Mode()&0o111 != 0
		}},
	{ruleID: "INITRAMFS_HOOK", paths: []string{"/etc/initramfs-tools/hooks", "/etc/initramfs-tools/scripts"}, signal: "initramfs_hook",
		match: func(_, _ string) bool { return true }},
	{ruleID: "GRUB_CMDLINE_CHANGE", paths: []string{"/etc/default/grub"}, signal: "grub_cmdline",
		match: func(_, full string) bool {
			b, err := os.ReadFile(full)
			if err != nil {
				return false
			}
			s := string(b)
			return strings.Contains(s, "init=") || strings.Contains(s, "apparmor=0") || strings.Contains(s, "selinux=0")
		}},
	{ruleID: "XDG_AUTOSTART_NEW", paths: []string{"/etc/xdg/autostart"}, signal: "xdg_autostart",
		match: func(name, _ string) bool { return strings.HasSuffix(name, ".desktop") }},
	{ruleID: "APPARMOR_PROFILE_DISABLED", paths: []string{"/etc/apparmor.d/disable"}, signal: "apparmor_disabled",
		match: func(_, _ string) bool { return true }},
	{ruleID: "RSYSLOG_CONFIG_TAMPER", paths: []string{"/etc/rsyslog.conf", "/etc/rsyslog.d"}, signal: "rsyslog_tamper",
		match: func(_, _ string) bool { return true }},
	{ruleID: "LOG_TRUNCATE", paths: []string{
		"/var/log/auth.log", "/var/log/syslog", "/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog", "/var/log/dpkg.log",
	}, signal: "log_truncate", match: func(_, full string) bool {
		st, err := os.Stat(full)
		return err == nil && st.Size() == 0
	}},
}

// Scan walks watched path classes and emits DELTA events vs baseline path hashes.
func Scan(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string) ([]event.Event, error) {
	var out []event.Event
	now := time.Now().UTC()
	learning := cfg.LearningMode || !snap.IsCommitted()
	if cfg.FirstRunAllowAlerts {
		learning = cfg.LearningMode
	}

	for _, pr := range ruleset {
		if pr.ruleID == "SYSTEMD_USER_PERSISTENCE" {
			out = append(out, scanUserSystemd(cfg, snap, pack, agentVer, now, learning)...)
			continue
		}
		for _, p := range pr.paths {
			st, err := os.Stat(p)
			if err != nil {
				continue
			}
			if !st.IsDir() {
				if pr.match != nil && !pr.match(filepath.Base(p), p) {
					continue
				}
				if ev, ok := emitIfNew(p, pr.ruleID, pr.signal, cfg, snap, pack, agentVer, now, learning); ok {
					out = append(out, ev)
				}
				continue
			}
			entries, err := os.ReadDir(p)
			if err != nil {
				continue
			}
			for _, e := range entries {
				full := filepath.Join(p, e.Name())
				if pr.match != nil && !pr.match(e.Name(), full) {
					continue
				}
				if ev, ok := emitIfNew(full, pr.ruleID, pr.signal, cfg, snap, pack, agentVer, now, learning); ok {
					out = append(out, ev)
				}
			}
		}
	}
	out = append(out, scanCronRunParts(cfg, snap, pack, agentVer, now, learning)...)
	out = append(out, scanSSHDForced(cfg, snap, pack, agentVer, now, learning)...)
	out = append(out, scanUserPrivGroups(cfg, snap, pack, agentVer, now, learning)...)
	return out, nil
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func emitIfNew(path, ruleID, signal string, cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string, now time.Time, learning bool) (event.Event, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		if _, err2 := os.Stat(path); err2 != nil {
			return event.Event{}, false
		}
		data = nil
	}
	sum := hashBytes(data)
	if snap.PersistenceFiles != nil {
		if prev, ok := snap.PersistenceFiles[path]; ok && prev == sum {
			return event.Event{}, false
		}
	}
	// First-seen while learning: record-only style (still emit learning_only).
	sigs := []string{signal, "path:" + path}
	conf, _ := rules.Score(pack, ruleID, sigs)
	if conf < 60 {
		conf = 60
	}
	ev := event.Event{
		SchemaVersion:   event.SchemaVersion,
		AgentVersion:    agentVer,
		Timestamp:       now,
		RuleID:          ruleID,
		RulePackVersion: pack.Version,
		Confidence:      conf,
		Severity:        rules.SeverityFromConfidence(conf, learning),
		Entity:          event.Entity{Type: event.EntityFile, ID: sum, Path: path},
		Signals:         sigs,
		Evidence:        path,
		LearningOnly:    learning || conf < cfg.MinConfidenceAlert,
		Src:             event.SrcFIM,
		Type:            event.TypeDelta,
	}
	ev.NormalizeDedup()
	return ev, true
}

func scanUserSystemd(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string, now time.Time, learning bool) []event.Event {
	var out []event.Event
	homes, _ := filepath.Glob("/home/*/.config/systemd/user")
	homes = append(homes, "/root/.config/systemd/user")
	for _, dir := range homes {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".service") && !strings.HasSuffix(e.Name(), ".timer") {
				continue
			}
			full := filepath.Join(dir, e.Name())
			if ev, ok := emitIfNew(full, "SYSTEMD_USER_PERSISTENCE", "systemd_user", cfg, snap, pack, agentVer, now, learning); ok {
				out = append(out, ev)
			}
		}
	}
	return out
}

func scanCronRunParts(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string, now time.Time, learning bool) []event.Event {
	var out []event.Event
	dirs := []string{"/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"}
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			// run-parts skips names with '.' or ending in '~'
			if !strings.Contains(name, ".") && !strings.HasSuffix(name, "~") {
				continue
			}
			full := filepath.Join(d, name)
			st, err := os.Stat(full)
			if err != nil || st.Mode()&0o111 == 0 {
				continue
			}
			if ev, ok := emitIfNew(full, "CRON_RUNPARTS_EVASION", "cron_runparts_evasion", cfg, snap, pack, agentVer, now, learning); ok {
				out = append(out, ev)
			}
		}
	}
	return out
}

func scanSSHDForced(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string, now time.Time, learning bool) []event.Event {
	var out []event.Event
	files := []string{"/etc/ssh/sshd_config"}
	if ents, err := filepath.Glob("/etc/ssh/sshd_config.d/*.conf"); err == nil {
		files = append(files, ents...)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		s := string(b)
		if !strings.Contains(s, "ForceCommand") && !strings.Contains(s, "AuthorizedKeysCommand") {
			continue
		}
		if ev, ok := emitIfNew(f, "SSHD_FORCED_COMMAND", "sshd_forced_command", cfg, snap, pack, agentVer, now, learning); ok {
			out = append(out, ev)
		}
	}
	return out
}

func scanUserPrivGroups(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string, now time.Time, learning bool) []event.Event {
	b, err := os.ReadFile("/etc/group")
	if err != nil {
		return nil
	}
	sum := hashBytes(b)
	path := "/etc/group"
	if snap.PersistenceFiles != nil {
		if prev, ok := snap.PersistenceFiles[path]; ok && prev == sum {
			return nil
		}
	}
	priv := map[string]struct{}{
		"sudo": {}, "admin": {}, "lxd": {}, "docker": {}, "microk8s": {},
		"adm": {}, "disk": {}, "shadow": {},
	}
	var hits []string
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}
		if _, ok := priv[parts[0]]; !ok {
			continue
		}
		if strings.TrimSpace(parts[3]) != "" {
			hits = append(hits, parts[0]+"="+parts[3])
		}
	}
	if len(hits) == 0 {
		return nil
	}
	sigs := []string{"user_priv_group", "groups:" + strings.Join(hits, ",")}
	conf, _ := rules.Score(pack, "USER_PRIV_GROUP_ADD", sigs)
	if conf < 70 {
		conf = 70
	}
	ev := event.Event{
		SchemaVersion:   event.SchemaVersion,
		AgentVersion:    agentVer,
		Timestamp:       now,
		RuleID:          "USER_PRIV_GROUP_ADD",
		RulePackVersion: pack.Version,
		Confidence:      conf,
		Severity:        rules.SeverityFromConfidence(conf, learning),
		Entity:          event.Entity{Type: event.EntityFile, ID: sum, Path: path},
		Signals:         sigs,
		Evidence:        strings.Join(hits, "; "),
		LearningOnly:    learning || conf < cfg.MinConfidenceAlert,
		Src:             event.SrcFIM,
		Type:            event.TypeDelta,
	}
	ev.NormalizeDedup()
	return []event.Event{ev}
}
