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
	RuleKmodNew       = "KERNEL_MODULE_NEW"
	RuleModLoadPathMod = "KERNEL_MODLOAD_PATH_CHANGED"
)

// kernelModulesFile is the canonical tree of loaded kernel modules.
const kernelModulesFile = "/proc/modules"

// moduleConfigDirs contain on-disk module-load persistence primitives.
// Writing `my.ko` into /etc/modules-load.d/ will cause systemd to load it on
// every boot; modprobe.d aliases can redirect legitimate module names.
var moduleConfigDirs = []string{
	"/etc/modules-load.d",
	"/etc/modprobe.d",
	"/usr/lib/modules-load.d",
	"/usr/lib/modprobe.d",
	"/run/modules-load.d",
}

var moduleConfigFiles = []string{
	"/etc/modules",
}

// scanKernelModules emits events when (a) currently-loaded module set has
// grown vs baseline, (b) any persistence file under moduleConfigDirs
// changed, or (c) a `taint` flag reveals an unsigned/out-of-tree module was
// loaded at runtime.
func scanKernelModules(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string, now time.Time) []event.Event {
	learning := cfg.LearningMode || !snap.IsCommitted()
	if cfg.FirstRunAllowAlerts {
		learning = cfg.LearningMode
	}
	var events []event.Event

	loaded := readLoadedModules()
	prev := map[string]struct{}{}
	for _, m := range snap.LoadedKernelModules {
		prev[m] = struct{}{}
	}
	var newMods []string
	for _, m := range loaded {
		if _, ok := prev[m]; !ok {
			newMods = append(newMods, m)
		}
	}
	if snap.IsCommitted() && len(newMods) > 0 {
		sigs := []string{"loaded_modules_delta", "new_modules:" + strings.Join(newMods, ",")}
		conf, _ := rules.Score(pack, RuleKmodNew, sigs)
		if conf < 80 {
			conf = 80
		}
		ev := event.Event{
			SchemaVersion:   event.SchemaVersion,
			AgentVersion:    agentVer,
			Timestamp:       now,
			RuleID:          RuleKmodNew,
			RulePackVersion: pack.Version,
			TechniqueIDs:    []string{"T1014"},
			Tactic:          "defense-evasion",
			Confidence:      conf,
			Severity:        rules.SeverityFromConfidence(conf, false),
			Entity:          event.Entity{Type: event.EntityFile, ID: "proc_modules", Path: kernelModulesFile},
			Signals:         sigs,
			Evidence:        "new kernel modules: " + strings.Join(newMods, ","),
			LearningOnly:    learning || conf < cfg.MinConfidenceAlert,
		}
		ev.NormalizeDedup()
		events = append(events, ev)
	}

	for _, path := range collectModuleConfigTargets() {
		hash := fileSHA(path)
		if hash == "" {
			continue
		}
		prev, inBase := snap.PersistenceFiles[path]
		if inBase && prev == hash {
			continue
		}
		sigs := []string{"modload_config_changed"}
		conf, _ := rules.Score(pack, RuleModLoadPathMod, sigs)
		ev := event.Event{
			SchemaVersion:   event.SchemaVersion,
			AgentVersion:    agentVer,
			Timestamp:       now,
			RuleID:          RuleModLoadPathMod,
			RulePackVersion: pack.Version,
			TechniqueIDs:    []string{"T1547.006"},
			Tactic:          "persistence",
			Confidence:      conf,
			Severity:        rules.SeverityFromConfidence(conf, learning),
			Entity:          event.Entity{Type: event.EntityFile, ID: hash, Path: path},
			Signals:         sigs,
			Evidence:        "module config changed since baseline",
			LearningOnly:    learning || conf < cfg.MinConfidenceAlert,
		}
		ev.NormalizeDedup()
		events = append(events, ev)
	}
	return events
}

func readLoadedModules() []string {
	f, err := os.Open(kernelModulesFile)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) > 0 {
			out = append(out, fields[0])
		}
	}
	return out
}

func collectModuleConfigTargets() []string {
	var out []string
	for _, f := range moduleConfigFiles {
		if _, err := os.Stat(f); err == nil {
			out = append(out, f)
		}
	}
	for _, d := range moduleConfigDirs {
		out = append(out, walkFiles(d)...)
	}
	return out
}

// BuildBaselineKernelModules captures the current loaded set and config hashes.
func BuildBaselineKernelModules(snap *baseline.Snapshot) error {
	snap.LoadedKernelModules = readLoadedModules()
	recordPersistenceBaseline(snap.PersistenceFiles, collectModuleConfigTargets())
	return nil
}
