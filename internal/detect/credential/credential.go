// Package credential implements Macro 5 credential-access nanos.
package credential

import (
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"ghostcatcher/internal/anchor"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/rules"
	"ghostcatcher/internal/sensor"
)

const (
	RuleShadowRead     = "SHADOW_READ_ANOMALY"
	RuleSSHPrivKey     = "SSH_PRIVKEY_ACCESS"
	RuleSSHAgentAbuse  = "SSH_AGENT_SOCKET_ABUSE"
	RuleCloudCred      = "CLOUD_CRED_FILE_ACCESS"
	RuleAppSecret      = "APP_SECRET_HARVEST"
	RuleMemReadCross   = "PROC_MEM_READ_CROSS_UID"
	RuleCredMassAccess = "CRED_MASS_FILE_ACCESS"
)

var expectedShadowReaders = map[string]struct{}{
	"unix_chkpwd": {}, "passwd": {}, "chage": {}, "login": {}, "sshd": {},
	"sudo": {}, "su": {}, "pam": {},
}

type massCounter struct {
	mu   sync.Mutex
	hits map[int][]time.Time
}

var mass = &massCounter{hits: map[int][]time.Time{}}

// RouteOpenat converts an audit/eBPF openat of a sensitive path into a M5 nano.
func RouteOpenat(cfg *config.Config, pack *rules.Pack, agentVer string, ev sensor.Event) (event.Event, bool) {
	path := strings.TrimSpace(ev.Path)
	if path == "" {
		path = strings.TrimSpace(ev.Extra["path"])
	}
	if path == "" {
		return event.Event{}, false
	}
	ruleID, sig := classifyCredPath(path)
	if ruleID == "" {
		return event.Event{}, false
	}
	ainfo := anchor.FromPID(ev.PID)
	if anchor.IsWatchedUnit(ainfo.SystemdUnit, cfg.FPAllowlistUnits) {
		return event.Event{}, false
	}
	if ruleID == RuleShadowRead {
		comm := strings.ToLower(ev.Comm)
		if _, ok := expectedShadowReaders[comm]; ok {
			return event.Event{}, false
		}
	}
	sigs := []string{sig, "path:" + path, "comm:" + ev.Comm}
	if ainfo.SystemdUnit != "" {
		sigs = append(sigs, "unit:"+ainfo.SystemdUnit)
	}
	conf, _ := rules.Score(pack, ruleID, sigs)
	if conf < 70 {
		conf = 70
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
		Entity: event.Entity{
			Type: event.EntityFile,
			ID:   path,
			Path: path,
		},
		Signals:  sigs,
		Evidence: path + " opened by " + ev.Comm,
		Src:      event.SrcAudit,
		Type:     event.TypeEvent,
		Anchor:   ainfo.Anchor,
		ConfBand: event.ConfHigh,
		Process: &event.ProcessContext{
			PID: ev.PID, Comm: ev.Comm, UID: int(ev.UID),
			Cgroup: ainfo.CgroupPath, SystemdUnit: ainfo.SystemdUnit,
		},
	}
	out.NormalizeDedup()

	if trackMass(ev.PID, now) {
		massEv := out
		massEv.RuleID = RuleCredMassAccess
		massEv.Signals = append([]string{"cred_mass_file_access"}, sigs...)
		massEv.ConfBand = event.ConfMedium
		massEv.NormalizeDedup()
		return massEv, true
	}
	return out, true
}

func classifyCredPath(path string) (string, string) {
	base := filepath.Base(path)
	switch {
	case path == "/etc/shadow" || path == "/etc/gshadow":
		return RuleShadowRead, "shadow_read"
	case strings.Contains(path, "/.ssh/id_") || strings.HasPrefix(path, "/etc/ssh/ssh_host_") && strings.HasSuffix(path, "_key"):
		return RuleSSHPrivKey, "ssh_privkey_access"
	case strings.Contains(path, "/.aws/credentials") ||
		strings.Contains(path, "/.config/gcloud/") ||
		strings.Contains(path, "/.azure/") ||
		strings.HasSuffix(path, "/.kube/config") ||
		strings.Contains(path, "/var/lib/kubelet/"):
		return RuleCloudCred, "cloud_cred_file_access"
	case base == ".env" || base == "wp-config.php" || base == "settings.py" ||
		base == "application.properties" || path == "/etc/mysql/debian.cnf":
		return RuleAppSecret, "app_secret_harvest"
	case strings.Contains(path, "/tmp/ssh-") && strings.Contains(path, "agent."):
		return RuleSSHAgentAbuse, "ssh_agent_socket_abuse"
	case strings.HasPrefix(path, "/proc/") && strings.HasSuffix(path, "/mem"):
		return RuleMemReadCross, "proc_mem_read"
	}
	return "", ""
}

func trackMass(pid int, now time.Time) bool {
	mass.mu.Lock()
	defer mass.mu.Unlock()
	cut := now.Add(-60 * time.Second)
	var kept []time.Time
	for _, t := range mass.hits[pid] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	mass.hits[pid] = kept
	return len(kept) > 8
}

// RoutePtraceMem flags process_vm_readv style cross-UID reads when Extra hints.
func RoutePtraceMem(cfg *config.Config, pack *rules.Pack, agentVer string, ev sensor.Event) (event.Event, bool) {
	if ev.Kind != sensor.KindPtrace {
		return event.Event{}, false
	}
	if ev.Extra["request"] != "" && !strings.Contains(strings.ToLower(ev.Extra["request"]), "peek") &&
		!strings.Contains(strings.ToLower(ev.Extra["request"]), "read") {
		return event.Event{}, false
	}
	ainfo := anchor.FromPID(ev.PID)
	sigs := []string{"proc_mem_read_cross_uid", "comm:" + ev.Comm}
	conf, _ := rules.Score(pack, RuleMemReadCross, sigs)
	if conf < 75 {
		conf = 75
	}
	now := time.Now().UTC()
	out := event.Event{
		SchemaVersion:   event.SchemaVersion,
		AgentVersion:    agentVer,
		Timestamp:       now,
		RuleID:          RuleMemReadCross,
		RulePackVersion: pack.Version,
		Confidence:      conf,
		Severity:        rules.SeverityFromConfidence(conf, cfg.LearningMode),
		Entity:          event.Entity{Type: event.EntityProcess, ID: strconv.Itoa(ev.PID)},
		Signals:         sigs,
		Evidence:        "ptrace/mem read by " + ev.Comm,
		Src:             event.SrcAudit,
		Type:            event.TypeEvent,
		Anchor:          ainfo.Anchor,
		ConfBand:        event.ConfHigh,
	}
	out.NormalizeDedup()
	return out, true
}
