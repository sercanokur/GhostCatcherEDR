// Package defense implements Macro 3.3 defense-weakening nanos and related
// live exec patterns (GTFOBins, AppArmor, firewall, sysctl).
package defense

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ghostcatcher/internal/anchor"
	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/rules"
	"ghostcatcher/internal/sensor"
)

const (
	RuleApparmorComplain = "APPARMOR_COMPLAIN_MODE"
	RuleApparmorUsns     = "APPARMOR_USERNS_RESTRICT_OFF"
	RuleSysctlHardening  = "SYSCTL_HARDENING_OFF"
	RuleAuditdTamper     = "AUDITD_TAMPER"
	RuleFirewallFlush    = "FIREWALL_FLUSH"
	RuleSecurityStop     = "SECURITY_SERVICE_STOP"
	RuleEBPFProgLoad     = "EBPF_PROGRAM_LOAD"
	RuleGTFOBin          = "GTFOBIN_EXEC"
	RuleUserNS           = "USERNS_UNPRIV_CREATE"
	RuleExecFromTmpfs    = "EXEC_FROM_TMPFS"
	RuleSnapDangerous    = "SNAP_DANGEROUS_INSTALL"
	RuleJournalVacuum    = "JOURNAL_VACUUM"
	RuleShellHistTamper  = "SHELL_HISTORY_TAMPER"
)

// ScanState checks sysctl / apparmor userns files for hardening regressions.
func ScanState(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string) ([]event.Event, error) {
	var out []event.Event
	now := time.Now().UTC()
	learning := cfg.LearningMode || !snap.IsCommitted()
	checks := []struct {
		path   string
		bad    string
		ruleID string
		sig    string
	}{
		{"/proc/sys/kernel/apparmor_restrict_unprivileged_userns", "0", RuleApparmorUsns, "apparmor_userns_off"},
		{"/proc/sys/kernel/yama/ptrace_scope", "0", RuleSysctlHardening, "yama_ptrace_scope_0"},
		{"/proc/sys/kernel/dmesg_restrict", "0", RuleSysctlHardening, "dmesg_restrict_0"},
		{"/proc/sys/kernel/kptr_restrict", "0", RuleSysctlHardening, "kptr_restrict_0"},
		{"/proc/sys/kernel/unprivileged_bpf_disabled", "0", RuleSysctlHardening, "unpriv_bpf_0"},
		{"/proc/sys/fs/protected_hardlinks", "0", RuleSysctlHardening, "protected_hardlinks_0"},
	}
	for _, c := range checks {
		b, err := os.ReadFile(c.path)
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(b)) != c.bad {
			continue
		}
		sigs := []string{c.sig, "path:" + c.path}
		conf, _ := rules.Score(pack, c.ruleID, sigs)
		if conf < 80 {
			conf = 80
		}
		ev := event.Event{
			SchemaVersion:   event.SchemaVersion,
			AgentVersion:    agentVer,
			Timestamp:       now,
			RuleID:          c.ruleID,
			RulePackVersion: pack.Version,
			Confidence:      conf,
			Severity:        rules.SeverityFromConfidence(conf, learning),
			Entity:          event.Entity{Type: event.EntityFile, ID: c.path, Path: c.path},
			Signals:         sigs,
			Evidence:        c.path + "=" + c.bad,
			LearningOnly:    learning || conf < cfg.MinConfidenceAlert,
			Src:             event.SrcAudit,
			Type:            event.TypeDelta,
			ConfBand:        event.ConfHigh,
		}
		ev.NormalizeDedup()
		out = append(out, ev)
	}
	return out, nil
}

// RouteExec classifies suspicious defense-weakening / privesc argv.
func RouteExec(cfg *config.Config, pack *rules.Pack, agentVer string, ev sensor.Event) (event.Event, bool) {
	line := strings.ToLower(strings.Join(ev.Argv, " "))
	if line == "" {
		line = strings.ToLower(ev.Comm + " " + ev.Path)
	}
	ainfo := anchor.FromPID(ev.PID)
	ruleID, sig := "", ""
	switch {
	case strings.Contains(line, "aa-complain") || strings.Contains(line, "aa-disable") ||
		strings.Contains(line, "apparmor_parser -r") || strings.Contains(line, "apparmor_parser -R"):
		ruleID, sig = RuleApparmorComplain, "apparmor_complain"
	case strings.Contains(line, "auditctl -e 0") || strings.Contains(line, "auditctl -d") ||
		strings.Contains(line, "systemctl stop auditd") || strings.Contains(line, "systemctl disable auditd"):
		ruleID, sig = RuleAuditdTamper, "auditd_tamper"
	case strings.Contains(line, "ufw disable") || strings.Contains(line, "iptables -f") ||
		strings.Contains(line, "nft flush ruleset"):
		ruleID, sig = RuleFirewallFlush, "firewall_flush"
	case strings.Contains(line, "systemctl stop apparmor") || strings.Contains(line, "systemctl mask apparmor") ||
		strings.Contains(line, "systemctl stop ufw") || strings.Contains(line, "systemctl stop fail2ban") ||
		strings.Contains(line, "systemctl stop snapd.apparmor"):
		ruleID, sig = RuleSecurityStop, "security_service_stop"
	case strings.Contains(line, "snap install") && (strings.Contains(line, "--dangerous") ||
		strings.Contains(line, "--devmode") || strings.Contains(line, "--classic")):
		ruleID, sig = RuleSnapDangerous, "snap_dangerous_install"
	case strings.Contains(line, "journalctl") && (strings.Contains(line, "--vacuum") || strings.Contains(line, "--rotate")):
		ruleID, sig = RuleJournalVacuum, "journal_vacuum"
	case strings.Contains(line, "history -c") || strings.Contains(line, "unset histfile") ||
		strings.Contains(line, "histfile="):
		ruleID, sig = RuleShellHistTamper, "shell_history_tamper"
	case isGTFOBin(line):
		ruleID, sig = RuleGTFOBin, "gtfobin_exec"
	case isTmpfsExec(ev.Path, line):
		ruleID, sig = RuleExecFromTmpfs, "exec_from_tmpfs"
	case strings.Contains(line, "unshare") && strings.Contains(line, "--user"):
		ruleID, sig = RuleUserNS, "userns_unpriv_create"
	default:
		return event.Event{}, false
	}
	sigs := []string{sig, "comm:" + ev.Comm}
	conf, _ := rules.Score(pack, ruleID, sigs)
	if conf < 65 {
		conf = 65
	}
	now := ev.When.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	out := event.Event{
		SchemaVersion:   event.SchemaVersion,
		AgentVersion:    agentVer,
		Timestamp:       now,
		RuleID:          ruleID,
		RulePackVersion: pack.Version,
		Confidence:      conf,
		Severity:        rules.SeverityFromConfidence(conf, cfg.LearningMode),
		Entity:          event.Entity{Type: event.EntityProcess, ID: strconv.Itoa(ev.PID), Path: ev.Path},
		Signals:         sigs,
		Evidence:        strings.Join(ev.Argv, " "),
		Src:             event.SrcAudit,
		Type:            event.TypeEvent,
		Anchor:          ainfo.Anchor,
		ConfBand:        event.ConfHigh,
	}
	if ruleID == RuleExecFromTmpfs || ruleID == RuleGTFOBin || ruleID == RuleUserNS {
		out.ConfBand = event.ConfMedium
	}
	out.NormalizeDedup()
	return out, true
}

func isGTFOBin(line string) bool {
	patterns := []string{
		"find ", " -exec",
		"vim ", " -c :!",
		"awk ", "system(",
		"tar ", "--checkpoint-action=exec",
		"env sh", "env bash",
	}
	// Simple combination checks.
	if strings.Contains(line, "find") && strings.Contains(line, "-exec") {
		return true
	}
	if strings.Contains(line, "vim") && strings.Contains(line, ":!") {
		return true
	}
	if strings.Contains(line, "awk") && strings.Contains(line, "system(") {
		return true
	}
	if strings.Contains(line, "tar") && strings.Contains(line, "--checkpoint-action=exec") {
		return true
	}
	if strings.HasPrefix(line, "env sh") || strings.HasPrefix(line, "env bash") {
		return true
	}
	_ = patterns
	return false
}

func isTmpfsExec(path, line string) bool {
	p := path
	if p == "" {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			p = fields[0]
		}
	}
	p = filepath.Clean(p)
	prefs := []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"}
	for _, pref := range prefs {
		if strings.HasPrefix(p, pref) {
			return true
		}
	}
	return false
}
