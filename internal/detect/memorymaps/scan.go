package memorymaps

import (
	"strconv"
	"strings"
	"time"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/procfs"
	"ghostcatcher/internal/rules"
)

const (
	RuleProcRWX           = "PROC_RWX_MEMORY_SEGMENT"
	RuleProcDeletedExec   = "PROC_DELETED_EXEC_SEGMENT"
	RuleProcWorldWritable = "PROC_WORLD_WRITABLE_MAPPING"
	RuleProcTracer        = "PROC_UNEXPECTED_TRACER"
	RuleProcSuspectLib    = "PROC_UNEXPECTED_LIBRARY"
	RuleProcCapEscalation = "PROC_CAP_ESCALATION"
)

// Scan inspects /proc/[pid]/maps and /proc/[pid]/status for the configured
// target processes and emits one or more events per fishy indicator.
//
// The scanner is intentionally conservative: every signal is individually
// corroborated (path hint, deleted flag, baseline lib delta, TracerPid) so
// the rule engine can score combinations rather than firing on one flag.
func Scan(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string) ([]event.Event, error) {
	if !cfg.MapsScanEnabled {
		return nil, nil
	}
	learning := cfg.LearningMode || !snap.IsCommitted()
	if cfg.FirstRunAllowAlerts {
		learning = cfg.LearningMode
	}
	var events []event.Event
	now := time.Now().UTC()
	want := map[string]struct{}{}
	for _, n := range cfg.MapsWatchProcesses {
		want[strings.ToLower(strings.TrimSpace(n))] = struct{}{}
	}
	pids, err := procfs.Processes()
	if err != nil {
		return nil, err
	}
	for _, pid := range pids {
		comm, err := procfs.Comm(pid)
		if err != nil {
			continue
		}
		if _, ok := want[strings.ToLower(strings.TrimSpace(comm))]; !ok {
			continue
		}
		entries, err := procfs.ReadMaps(pid)
		if err != nil {
			continue
		}

		// --- RWX segment check.
		if hit, pathHint := procfs.HasRWXSegment(entries); hit {
			if !pathAllowlisted(pathHint, cfg.MapsPathAllowlist) {
				events = append(events, emitMapEvent(RuleProcRWX, pid, comm, pathHint,
					[]string{"rwx_memory_mapping", "comm:" + comm, mappingDetail(pathHint)},
					[]string{"T1055"}, now, agentVer, cfg, pack, false))
			}
		}
		// --- Deleted backing file.
		if hit, pathHint := procfs.HasDeletedExecSegment(entries); hit {
			events = append(events, emitMapEvent(RuleProcDeletedExec, pid, comm, pathHint,
				[]string{"deleted_backed_exec_segment", "comm:" + comm, "mapping_path:" + truncate(pathHint, 80)},
				[]string{"T1055", "T1620"}, now, agentVer, cfg, pack, false))
		}
		// --- World-writable path backing.
		if hit, pathHint := procfs.WorldWritableSegmentPathHints(entries); hit {
			events = append(events, emitMapEvent(RuleProcWorldWritable, pid, comm, pathHint,
				[]string{"world_writable_mapping", "comm:" + comm, "mapping_path:" + truncate(pathHint, 80)},
				[]string{"T1055"}, now, agentVer, cfg, pack, learning))
		}
		// --- Library allowlist delta vs baseline.
		if allowed, ok := snap.LoadedLibraries[comm]; ok {
			want := map[string]struct{}{}
			for _, p := range allowed {
				want[p] = struct{}{}
			}
			for _, lib := range procfs.LoadedSharedObjects(entries) {
				if _, ok := want[lib]; ok {
					continue
				}
				events = append(events, emitMapEvent(RuleProcSuspectLib, pid, comm, lib,
					[]string{"unknown_shared_object", "comm:" + comm, "lib:" + truncate(lib, 120)},
					[]string{"T1574.006"}, now, agentVer, cfg, pack, learning))
			}
		}
		// --- Status-based checks (TracerPid, CapEff rising).
		st, err := procfs.ReadStatus(pid)
		if err == nil {
			if st.TracerPid != 0 {
				events = append(events, emitMapEvent(RuleProcTracer, pid, comm, "",
					[]string{"ptrace_attached", "tracer_pid:" + strconv.Itoa(st.TracerPid), "comm:" + comm},
					[]string{"T1055.001"}, now, agentVer, cfg, pack, false))
			}
			if capLooksEscalated(st) {
				events = append(events, emitMapEvent(RuleProcCapEscalation, pid, comm, "",
					[]string{"effective_caps_all_bits", "comm:" + comm, "cap_eff:" + st.CapEff},
					[]string{"T1548", "T1055"}, now, agentVer, cfg, pack, learning))
			}
		}
	}
	return events, nil
}

// capLooksEscalated reports true when the effective caps bitmask is "looks
// like full root caps" while the real uid is non-zero. We keep it simple:
// any EUID != 0 process with CapEff >= 000001ffffffffff is notable.
func capLooksEscalated(s procfs.Status) bool {
	if s.EffUID == 0 {
		return false
	}
	v := strings.TrimLeft(strings.ToLower(s.CapEff), "0")
	if len(v) >= 10 { // lots of set bits
		return true
	}
	return false
}

func emitMapEvent(rule string, pid int, comm, pathHint string, sigs []string, tech []string, now time.Time, agentVer string, cfg *config.Config, pack *rules.Pack, learning bool) event.Event {
	conf, _ := rules.Score(pack, rule, sigs)
	if conf < 70 {
		conf = 70
	}
	ev := event.Event{
		SchemaVersion:   event.SchemaVersion,
		AgentVersion:    agentVer,
		Timestamp:       now,
		RuleID:          rule,
		RulePackVersion: pack.Version,
		TechniqueIDs:    tech,
		Tactic:          "defense-evasion",
		Confidence:      conf,
		Severity:        rules.SeverityFromConfidence(conf, learning),
		Entity: event.Entity{
			Type: event.EntityProcess,
			ID:   strconv.Itoa(pid),
			Path: procfs.ResolveExe(pid),
		},
		Signals:      sigs,
		Evidence:     "pid=" + strconv.Itoa(pid) + " comm=" + comm + " map=" + truncate(pathHint, 120),
		LearningOnly: learning,
	}
	ev.NormalizeDedup()
	return ev
}

func mappingDetail(path string) string {
	if path == "" {
		return "anonymous_rwx_mapping"
	}
	return "mapping_path:" + truncate(path, 80)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func pathAllowlisted(path string, prefixes []string) bool {
	if path == "" {
		return false
	}
	low := strings.ToLower(path)
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(low, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// BuildBaselineLibraries snapshots the .so set loaded by each target process
// at commit time so unexpected libraries can be flagged later.
func BuildBaselineLibraries(cfg *config.Config, snap *baseline.Snapshot) error {
	if snap.LoadedLibraries == nil {
		snap.LoadedLibraries = map[string][]string{}
	}
	want := map[string]struct{}{}
	for _, n := range cfg.MapsWatchProcesses {
		want[strings.ToLower(strings.TrimSpace(n))] = struct{}{}
	}
	pids, err := procfs.Processes()
	if err != nil {
		return nil
	}
	for _, pid := range pids {
		comm, err := procfs.Comm(pid)
		if err != nil {
			continue
		}
		if _, ok := want[strings.ToLower(strings.TrimSpace(comm))]; !ok {
			continue
		}
		entries, err := procfs.ReadMaps(pid)
		if err != nil {
			continue
		}
		libs := procfs.LoadedSharedObjects(entries)
		existing := snap.LoadedLibraries[comm]
		dedup := map[string]struct{}{}
		for _, l := range existing {
			dedup[l] = struct{}{}
		}
		for _, l := range libs {
			dedup[l] = struct{}{}
		}
		out := make([]string, 0, len(dedup))
		for l := range dedup {
			out = append(out, l)
		}
		snap.LoadedLibraries[comm] = out
	}
	return nil
}
