// Package containeresc implements Macro 6 container/virt boundary nanos.
package containeresc

import (
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ghostcatcher/internal/anchor"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/rules"
	"ghostcatcher/internal/sensor"
)

const (
	RuleSocketAccess    = "CONTAINER_SOCKET_ACCESS"
	RuleHostMount       = "CONTAINER_HOST_MOUNT"
	RuleRuncSelfExe     = "RUNC_SELF_EXE_WRITE"
	RuleCgroupRelease   = "CGROUP_RELEASE_AGENT_WRITE"
	RulePrivilegedStart = "CONTAINER_PRIVILEGED_START"
	RuleLXDHostDisk     = "LXD_HOST_DISK_ATTACH"
	RuleNSEscapeSetns   = "NS_ESCAPE_SETNS"
)

var containerSockets = []string{
	"/var/run/docker.sock",
	"/run/docker.sock",
	"/run/containerd/containerd.sock",
	"/var/snap/lxd/common/lxd/unix.socket",
}

// RouteFile maps openat/write paths to container-escape nanos.
func RouteFile(cfg *config.Config, pack *rules.Pack, agentVer string, ev sensor.Event) (event.Event, bool) {
	path := strings.TrimSpace(ev.Path)
	if path == "" {
		path = strings.TrimSpace(ev.Extra["path"])
	}
	if path == "" {
		return event.Event{}, false
	}
	ainfo := anchor.FromPID(ev.PID)
	ruleID, sig := "", ""
	switch {
	case isContainerSocket(path):
		ruleID, sig = RuleSocketAccess, "container_socket_access"
	case strings.Contains(path, "release_agent") || strings.Contains(path, "notify_on_release"):
		ruleID, sig = RuleCgroupRelease, "cgroup_release_agent_write"
	case path == "/proc/self/exe" || strings.HasSuffix(path, "/exe"):
		ruleID, sig = RuleRuncSelfExe, "runc_self_exe_write"
	default:
		return event.Event{}, false
	}
	return build(cfg, pack, agentVer, ev, ainfo, ruleID, sig, path), true
}

// RouteExec maps container runtime argv patterns.
func RouteExec(cfg *config.Config, pack *rules.Pack, agentVer string, ev sensor.Event) (event.Event, bool) {
	line := strings.Join(ev.Argv, " ")
	if line == "" {
		line = ev.Extra["exe"] + " " + ev.Comm
	}
	low := strings.ToLower(line)
	ainfo := anchor.FromPID(ev.PID)
	ruleID, sig := "", ""
	switch {
	case strings.Contains(low, "--privileged") || strings.Contains(low, "--pid=host") ||
		strings.Contains(low, "--net=host") || strings.Contains(low, "-v /:/") ||
		strings.Contains(low, "--cap-add=sys_admin"):
		ruleID, sig = RulePrivilegedStart, "container_privileged_start"
	case strings.Contains(low, "lxc config device add") && strings.Contains(low, "source=/"):
		ruleID, sig = RuleLXDHostDisk, "lxd_host_disk_attach"
	case strings.Contains(low, "nsenter") && (strings.Contains(low, "--target 1") || strings.Contains(low, "-t 1")):
		ruleID, sig = RuleHostMount, "container_host_mount"
	case strings.Contains(low, "mount") && (strings.Contains(low, " / ") || strings.Contains(low, "source=/")):
		ruleID, sig = RuleHostMount, "container_host_mount"
	default:
		return event.Event{}, false
	}
	return build(cfg, pack, agentVer, ev, ainfo, ruleID, sig, line), true
}

// RouteSetns maps setns syscalls (when sensor exposes them via Extra).
func RouteSetns(cfg *config.Config, pack *rules.Pack, agentVer string, ev sensor.Event) (event.Event, bool) {
	if !strings.Contains(strings.ToLower(ev.Extra["syscall"]), "setns") &&
		ev.Kind != sensor.KindExec {
		return event.Event{}, false
	}
	if ev.Extra["syscall"] == "" && !strings.Contains(strings.ToLower(strings.Join(ev.Argv, " ")), "setns") {
		return event.Event{}, false
	}
	ainfo := anchor.FromPID(ev.PID)
	return build(cfg, pack, agentVer, ev, ainfo, RuleNSEscapeSetns, "ns_escape_setns", ev.Comm), true
}

func isContainerSocket(path string) bool {
	for _, s := range containerSockets {
		if path == s || filepath.Clean(path) == s {
			return true
		}
	}
	return false
}

func build(cfg *config.Config, pack *rules.Pack, agentVer string, ev sensor.Event, ainfo anchor.Info, ruleID, sig, evidence string) event.Event {
	sigs := []string{sig, "comm:" + ev.Comm}
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
		Entity:          event.Entity{Type: event.EntityProcess, ID: strconv.Itoa(ev.PID), Path: ev.Path},
		Signals:         sigs,
		Evidence:        evidence,
		Src:             event.SrcAudit,
		Type:            event.TypeEvent,
		Anchor:          ainfo.Anchor,
		ConfBand:        event.ConfHigh,
	}
	out.NormalizeDedup()
	return out
}
