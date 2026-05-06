package integrity

import (
	"bufio"
	"bytes"
	"os/exec"
	"strings"
	"time"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/rules"
)

// scanRPM shells out to `rpm -Va` - the canonical, distro-shipped RHEL/Fedora/
// Rocky/SUSE integrity verification tool - and reports each file whose
// verification produced a failure character for the interested attributes.
//
// The columns (8 chars + file-type + path) are documented in rpm(8).
//   S = size differs
//   M = mode differs
//   5 = digest (md5/sha256) differs
//   D = device mismatch
//   L = symlink target differs
//   U = user differs
//   G = group differs
//   T = mtime differs
//   P = capabilities differ
//
// The agent filters to binaries under cfg.IntegrityPaths when the list is
// non-empty; otherwise every failure is emitted.
func scanRPM(cfg *config.Config, _ *baseline.Snapshot, pack *rules.Pack, agentVer string, now time.Time) []event.Event {
	cmd := exec.Command("rpm", "--nosignature", "-Va")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	_ = cmd.Run() // rpm -Va exits non-zero when anomalies exist; output is still the signal

	paths := map[string]struct{}{}
	for _, p := range cfg.IntegrityPaths {
		paths[p] = struct{}{}
	}

	var events []event.Event
	sc := bufio.NewScanner(&out)
	for sc.Scan() {
		line := sc.Text()
		if len(line) < 12 {
			continue
		}
		// Field layout: "SM5DLUGT P c /path/..."
		// Split on whitespace, last element is the path (no spaces expected in binary paths we care about).
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		path := fields[len(fields)-1]
		flags := fields[0]
		if !strings.ContainsAny(flags, "5MUGT P") {
			continue
		}
		if len(paths) > 0 {
			if _, ok := paths[path]; !ok {
				continue
			}
		}
		sigs := []string{"rpm_va_mismatch", "flags:" + flags}
		if strings.Contains(flags, "5") {
			sigs = append(sigs, "digest_mismatch")
		}
		conf, _ := rules.Score(pack, RuleBinaryMD5Mismatch, sigs)
		if conf < 85 {
			conf = 85
		}
		ev := event.Event{
			SchemaVersion:   event.SchemaVersion,
			AgentVersion:    agentVer,
			Timestamp:       now,
			RuleID:          RuleBinaryMD5Mismatch,
			RulePackVersion: pack.Version,
			TechniqueIDs:    []string{"T1036", "T1574.006"},
			Tactic:          "defense-evasion",
			Confidence:      conf,
			Severity:        rules.SeverityFromConfidence(conf, false),
			Entity:          event.Entity{Type: event.EntityFile, ID: path, Path: path},
			Signals:         sigs,
			Evidence:        line,
			LearningOnly:    false,
		}
		ev.NormalizeDedup()
		events = append(events, ev)
	}
	return events
}
