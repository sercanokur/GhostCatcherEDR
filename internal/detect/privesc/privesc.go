// Package privesc detects behavioral privilege escalation: a process
// instance that was previously unprivileged gains euid=0 (or a near-full
// CapEff set) without matching a known legitimate escalation helper.
//
// This is deliberately CVE-agnostic. It does not look for futex/requeue
// tradecraft or any other exploit primitive — only for sudden root as an
// outcome anomaly, with allowlists to suppress sudo/su/pkexec/sshd noise.
package privesc

import (
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ghostcatcher/internal/config"
	"ghostcatcher/internal/container"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/procfs"
	"ghostcatcher/internal/rules"
	"ghostcatcher/internal/sensor"
)

// RuleSuddenRoot is the behavior-only sudden-root rule ID.
const RuleSuddenRoot = "PROC_SUDDEN_ROOT"

// DefaultAllowedExeBasenames are common setuid / login helpers that
// legitimately flip credentials in-process around exec.
var DefaultAllowedExeBasenames = []string{
	"sudo", "sudoedit", "su", "pkexec", "doas",
	"login", "sshd", "passwd", "chsh", "chfn", "newgrp", "gpasswd",
	"mount", "umount", "fusermount", "fusermount3",
	"ping", "ping6", "traceroute", "traceroute6",
	"crontab", "at", "newuidmap", "newgidmap",
}

// DefaultAllowedAncestorComms suppress transitions whose parent chain
// clearly shows an allowed privilege broker (setuid helpers only).
// Broad service parents like sshd/systemd are intentionally excluded so
// a kernel LPE from an interactive user session is still visible.
var DefaultAllowedAncestorComms = []string{
	"sudo", "su", "pkexec", "doas", "login",
}

// Snapshot walks every visible PID, observes credentials into tracker,
// and returns sudden-root detection events.
func Snapshot(cfg *config.Config, pack *rules.Pack, agentVer string, tracker *Tracker) ([]event.Event, error) {
	if cfg == nil || tracker == nil || !cfg.SuddenRoot.Enabled {
		return nil, nil
	}
	pids, err := procfs.Processes()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	live := make(map[ProcessKey]struct{}, len(pids))
	var out []event.Event
	for _, pid := range pids {
		st, key, ok := readCred(pid, now)
		if !ok {
			continue
		}
		live[key] = struct{}{}
		tr := tracker.Observe(key, st)
		if tr == nil {
			continue
		}
		if ev, hit := buildEvent(cfg, pack, agentVer, tr); hit {
			out = append(out, ev)
		}
	}
	tracker.RetainOnly(live)
	return out, nil
}

// RouteSensorEvent seeds / re-observes credentials for an execve target
// so short-lived in-process escalations are caught without waiting for
// the next periodic snapshot.
func RouteSensorEvent(cfg *config.Config, pack *rules.Pack, agentVer string, tracker *Tracker, ev sensor.Event) (event.Event, bool) {
	if cfg == nil || tracker == nil || !cfg.SuddenRoot.Enabled {
		return event.Event{}, false
	}
	if ev.Kind != sensor.KindExec || ev.PID <= 0 {
		return event.Event{}, false
	}
	now := ev.When
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	st, key, ok := readCred(ev.PID, now)
	if !ok {
		return event.Event{}, false
	}
	// Prefer sensor-provided paths when /proc lags behind a fresh exec.
	if st.Comm == "" && ev.Comm != "" {
		st.Comm = ev.Comm
	}
	if st.Exe == "" && ev.Path != "" {
		st.Exe = ev.Path
	}
	tr := tracker.Observe(key, st)
	if tr == nil {
		return event.Event{}, false
	}
	return buildEvent(cfg, pack, agentVer, tr)
}

func readCred(pid int, now time.Time) (CredState, ProcessKey, bool) {
	start, err := procfs.ReadStartTime(pid)
	if err != nil {
		return CredState{}, ProcessKey{}, false
	}
	st, err := procfs.ReadStatus(pid)
	if err != nil {
		return CredState{}, ProcessKey{}, false
	}
	comm := st.Name
	if c, err := procfs.Comm(pid); err == nil && c != "" {
		comm = c
	}
	ppid, _ := procfs.PPid(pid)
	cs := CredState{
		UID:       st.RealUID,
		EUID:      st.EffUID,
		CapEff:    st.CapEff,
		Comm:      comm,
		Exe:       procfs.ResolveExe(pid),
		PPID:      ppid,
		Ancestors: procfs.Ancestry(pid, 6),
		SeenAt:    now,
	}
	if cg, err := procfs.ReadCgroup(pid); err == nil {
		info := container.Classify(cg)
		cs.Container = info.Runtime
	}
	return cs, ProcessKey{PID: pid, StartTime: start}, true
}

func buildEvent(cfg *config.Config, pack *rules.Pack, agentVer string, tr *Transition) (event.Event, bool) {
	if isAllowlisted(cfg, tr) {
		return event.Event{}, false
	}

	sigs := []string{
		"cred_transition",
		"transition:" + tr.Kind,
		"prev_uid:" + strconv.Itoa(tr.Prev.UID),
		"prev_euid:" + strconv.Itoa(tr.Prev.EUID),
		"new_euid:" + strconv.Itoa(tr.Curr.EUID),
		"comm:" + tr.Curr.Comm,
	}
	if tr.Curr.CapEff != "" {
		sigs = append(sigs, "capeff:"+tr.Curr.CapEff)
	}
	if tr.Prev.CapEff != "" && tr.Prev.CapEff != tr.Curr.CapEff {
		sigs = append(sigs, "prev_capeff:"+tr.Prev.CapEff)
	}

	exe := tr.Curr.Exe
	base := strings.ToLower(filepath.Base(stripDeletedSuffix(exe)))
	switch {
	case strings.Contains(exe, "memfd:"):
		sigs = append(sigs, "exe_memfd")
	case strings.Contains(exe, "(deleted)"):
		sigs = append(sigs, "exe_deleted")
	case isTempPath(exe):
		sigs = append(sigs, "exe_temp_path")
	case base != "" && !isDefaultAllowedBasename(base):
		sigs = append(sigs, "exe_outside_helper_allowlist")
	}
	if tr.Curr.Container != "" {
		sigs = append(sigs, "container:"+tr.Curr.Container)
	}
	if !ancestorAllowlisted(cfg, tr.Curr.Ancestors) && !ancestorAllowlisted(cfg, []string{ancestorComm(tr)}) {
		sigs = append(sigs, "unexpected_ancestry")
	}

	conf, ok := rules.Score(pack, RuleSuddenRoot, sigs)
	if !ok {
		conf = 80
	}
	// Floor by transition quality so pack tuning cannot mute high-signal cases.
	minFloor := 80
	if containsAny(sigs, "exe_memfd", "exe_deleted", "exe_temp_path") {
		minFloor = 90
	}
	if containsAny(sigs, "container:") && containsAny(sigs, "exe_outside_helper_allowlist") {
		minFloor = 92
	}
	if conf < minFloor {
		conf = minFloor
	}

	learning := cfg.LearningMode
	out := event.Event{
		SchemaVersion:   event.SchemaVersion,
		AgentVersion:    agentVer,
		Timestamp:       tr.SeenAt,
		RuleID:          RuleSuddenRoot,
		RulePackVersion: pack.Version,
		TechniqueIDs:    []string{"T1068"},
		Tactic:          "privilege-escalation",
		Confidence:      conf,
		Severity:        rules.SeverityFromConfidence(conf, learning),
		Entity: event.Entity{
			Type: event.EntityProcess,
			ID:   strconv.Itoa(tr.Key.PID),
			Path: exe,
		},
		Signals: sigs,
		Evidence: "sudden_root pid=" + strconv.Itoa(tr.Key.PID) +
			" starttime=" + strconv.FormatUint(tr.Key.StartTime, 10) +
			" " + tr.Kind +
			" uid " + strconv.Itoa(tr.Prev.UID) + "/" + strconv.Itoa(tr.Prev.EUID) +
			" → " + strconv.Itoa(tr.Curr.UID) + "/" + strconv.Itoa(tr.Curr.EUID) +
			" exe=" + exe,
		LearningOnly: learning,
		Process: &event.ProcessContext{
			PID:           tr.Key.PID,
			PPID:          tr.Curr.PPID,
			Comm:          tr.Curr.Comm,
			Exe:           exe,
			UID:           tr.Curr.UID,
			EUID:          tr.Curr.EUID,
			CapEff:        tr.Curr.CapEff,
			AncestorComms: append([]string(nil), tr.Curr.Ancestors...),
		},
	}
	if tr.Curr.Container != "" {
		out.Container = &event.ContainerContext{Runtime: tr.Curr.Container}
	}
	out.NormalizeDedup()
	return out, true
}

func isAllowlisted(cfg *config.Config, tr *Transition) bool {
	bases := allowedExeSet(cfg.SuddenRoot.AllowedExeBasenames)
	currBase := strings.ToLower(filepath.Base(stripDeletedSuffix(tr.Curr.Exe)))
	prevBase := strings.ToLower(filepath.Base(stripDeletedSuffix(tr.Prev.Exe)))
	currComm := strings.ToLower(tr.Curr.Comm)
	prevComm := strings.ToLower(tr.Prev.Comm)

	if _, ok := bases[currBase]; ok {
		return true
	}
	if _, ok := bases[currComm]; ok {
		return true
	}
	// setuid helpers often change exe on the same PID (bash fork → exec sudo).
	if _, ok := bases[prevBase]; ok {
		return true
	}
	if _, ok := bases[prevComm]; ok {
		return true
	}
	if ancestorAllowlisted(cfg, tr.Curr.Ancestors) {
		return true
	}
	return false
}

func ancestorAllowlisted(cfg *config.Config, ancs []string) bool {
	allowed := allowedAncestorSet(cfg.SuddenRoot.AllowedAncestorComms)
	for _, a := range ancs {
		if _, ok := allowed[strings.ToLower(strings.TrimSpace(a))]; ok {
			return true
		}
	}
	return false
}

func ancestorComm(tr *Transition) string {
	if len(tr.Curr.Ancestors) > 0 {
		return tr.Curr.Ancestors[0]
	}
	return ""
}

func allowedExeSet(extra []string) map[string]struct{} {
	out := make(map[string]struct{}, len(DefaultAllowedExeBasenames)+len(extra))
	for _, b := range DefaultAllowedExeBasenames {
		out[strings.ToLower(b)] = struct{}{}
	}
	for _, b := range extra {
		b = strings.ToLower(strings.TrimSpace(b))
		if b != "" {
			out[b] = struct{}{}
		}
	}
	return out
}

func allowedAncestorSet(extra []string) map[string]struct{} {
	out := make(map[string]struct{}, len(DefaultAllowedAncestorComms)+len(extra))
	for _, b := range DefaultAllowedAncestorComms {
		out[strings.ToLower(b)] = struct{}{}
	}
	for _, b := range extra {
		b = strings.ToLower(strings.TrimSpace(b))
		if b != "" {
			out[b] = struct{}{}
		}
	}
	return out
}

func isDefaultAllowedBasename(base string) bool {
	_, ok := allowedExeSet(nil)[base]
	return ok
}

func stripDeletedSuffix(exe string) string {
	return strings.TrimSpace(strings.TrimSuffix(exe, " (deleted)"))
}

func isTempPath(exe string) bool {
	low := strings.ToLower(exe)
	return strings.HasPrefix(low, "/tmp/") ||
		strings.HasPrefix(low, "/var/tmp/") ||
		strings.HasPrefix(low, "/dev/shm/") ||
		strings.HasPrefix(low, "/run/user/")
}

func containsAny(sigs []string, prefixes ...string) bool {
	for _, s := range sigs {
		for _, p := range prefixes {
			if p == s || strings.HasPrefix(s, p) {
				return true
			}
		}
	}
	return false
}
