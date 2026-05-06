package web

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/procfs"
	"ghostcatcher/internal/rules"
)

const RuleWebShell = "WEB_SHELL_PATTERN"

// entropyThreshold - files whose Shannon entropy exceeds this on ASCII-like
// content are almost certainly packed or encoded payloads. 7.5 bits/byte is
// the conventional "looks like ciphertext" boundary.
const entropyThreshold = 7.5

// smallWebshellBytes - below this size a "tiny file that only evals user input"
// is treated as near-definitive webshell, matching china-chopper tradecraft.
const smallWebshellBytes = 512

var shellChildPattern = regexp.MustCompile(`(?i)/(ba)?sh$|perl|python[0-9.]*$|php$`)

// Scan walks every document root emitting WEB_SHELL_PATTERN events for
// suspicious PHP/JSP/ASP(X) files plus polyglot polyfills with mismatched
// magic bytes. Signals combine content patterns with host context (setuid,
// ownership, recent mtime, new vs baseline) and process-tree correlation.
func Scan(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string) ([]event.Event, error) {
	var events []event.Event
	now := time.Now().UTC()
	learning := cfg.LearningMode || !snap.IsCommitted()
	if cfg.FirstRunAllowAlerts {
		learning = cfg.LearningMode
	}

	webWorkers := findWebWorkerPIDs(cfg)
	hasShellChild := map[int]bool{}
	for pid := range webWorkers {
		if treeHasShellChild(pid, cfg) {
			hasShellChild[pid] = true
		}
	}

	for _, root := range cfg.DocumentRoots {
		root = filepath.Clean(root)
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if pathAllowlisted(path, cfg.PathAllowlist) {
				return nil
			}
			st, err := d.Info()
			if err != nil {
				return nil
			}
			// Only read files that are script-like by name or small enough
			// to be worth a magic-byte polyglot check.
			suspicious := hasSuspiciousExtension(path)
			if !suspicious && st.Size() > 1<<20 {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			polyglot := magicByteMismatch(path, data)
			if !suspicious && !polyglot {
				return nil
			}

			ev, ok := evaluateWebFile(path, data, st, cfg, snap, pack, agentVer, now,
				webWorkers, hasShellChild, learning, polyglot)
			if ok {
				events = append(events, ev)
			}
			return nil
		})
	}
	return events, nil
}

func evaluateWebFile(
	path string,
	data []byte,
	st fs.FileInfo,
	cfg *config.Config,
	snap *baseline.Snapshot,
	pack *rules.Pack,
	agentVer string,
	now time.Time,
	webWorkers map[int]struct{},
	hasShellChild map[int]bool,
	learning bool,
	polyglot bool,
) (event.Event, bool) {
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	rec, inBase := snap.WebFiles[path]
	recent := time.Since(st.ModTime()) <= time.Duration(cfg.WebRecentDays)*24*time.Hour
	newOrChanged := !inBase || rec.SHA256 != hash

	matched := matchingPatterns(string(data))
	ent := shannonEntropy(data)
	fa := readFileAttributes(st)
	phpTaint, phpSink := false, ""
	if strings.HasSuffix(strings.ToLower(path), ".php") || strings.HasSuffix(strings.ToLower(path), ".phar") || strings.HasSuffix(strings.ToLower(path), ".phtml") {
		phpTaint, phpSink = scanPHPTaintFlow(string(data))
	}

	// Aggregate signals before deciding severity tier.
	var sigs []string
	if len(matched) > 0 {
		sigs = append(sigs, "suspicious_web_pattern:"+strings.Join(matched, ","))
	}
	if phpTaint {
		sigs = append(sigs, "php_taint_flow:"+phpSink)
	}
	if ent >= entropyThreshold {
		sigs = append(sigs, "high_entropy_content")
	}
	if polyglot {
		sigs = append(sigs, "polyglot_magic_mismatch")
	}
	if fa.SetUID {
		sigs = append(sigs, "setuid_script_file")
	}
	if fa.SetGID {
		sigs = append(sigs, "setgid_script_file")
	}
	if fa.OwnerUID != 0 && ownerLooksLikeWebUser(fa.OwnerUID) {
		sigs = append(sigs, "owned_by_web_user")
	}
	if st.Size() <= smallWebshellBytes && len(matched) > 0 {
		sigs = append(sigs, "tiny_high_signal_file")
	}

	childSig := false
	for wpid := range webWorkers {
		if hasShellChild[wpid] {
			sigs = append(sigs, "web_worker_shell_child")
			childSig = true
			break
		}
	}
	if newOrChanged {
		sigs = append(sigs, "file_new_or_changed_vs_baseline")
	}
	if recent {
		sigs = append(sigs, "mtime_within_recent_window")
	}

	// Abort entirely if nothing interesting turned up.
	if len(sigs) == 0 {
		return event.Event{}, false
	}
	// Baseline-matched files without content match only report if polyglot/entropy/taint.
	if len(matched) == 0 && !polyglot && ent < entropyThreshold && !phpTaint {
		return event.Event{}, false
	}

	// After baseline commit, a recent mtime alone is not escalation-worthy.
	high := (len(matched) > 0 || phpTaint) && (childSig || newOrChanged || polyglot ||
		(!snap.IsCommitted() && recent))

	tech := []string{"T1505.003"}
	if childSig {
		tech = append(tech, "T1059.004")
		sigs = append(sigs, "correlated_T1059")
	}

	confidence, _ := rules.Score(pack, RuleWebShell, sigs)
	if !high {
		confidence = minInt(confidence, 50)
		return event.Event{
			SchemaVersion:   event.SchemaVersion,
			AgentVersion:    agentVer,
			Timestamp:       now,
			RuleID:          RuleWebShell,
			RulePackVersion: pack.Version,
			TechniqueIDs:    tech,
			Tactic:          "persistence",
			Confidence:      confidence,
			Severity:        event.SeverityInfo,
			Entity:          event.Entity{Type: event.EntityFile, ID: hash, Path: path},
			Signals:         sigs,
			Evidence:        evidenceSnippet(string(data), matched, ent),
			LearningOnly:    true,
		}, true
	}

	return event.Event{
		SchemaVersion:   event.SchemaVersion,
		AgentVersion:    agentVer,
		Timestamp:       now,
		RuleID:          RuleWebShell,
		RulePackVersion: pack.Version,
		TechniqueIDs:    tech,
		Tactic:          "persistence",
		Confidence:      confidence,
		Severity:        rules.SeverityFromConfidence(confidence, learning),
		Entity:          event.Entity{Type: event.EntityFile, ID: hash, Path: path},
		Signals:         sigs,
		Evidence:        evidenceSnippet(string(data), matched, ent),
		LearningOnly:    learning || confidence < cfg.MinConfidenceAlert,
	}, true
}

// ownerLooksLikeWebUser uses a small hard-coded UID set common across Debian/Ubuntu
// (33 = www-data) and RHEL/CentOS (48 = apache). Hosts with unusual layouts can
// rely on path allowlists; this is purely a corroborating sub-signal.
func ownerLooksLikeWebUser(uid uint32) bool {
	return uid == 33 || uid == 48 || uid == 99
}

func pathAllowlisted(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(path, filepath.Clean(p)) {
			return true
		}
	}
	return false
}

func evidenceSnippet(content string, matched []string, entropy float64) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		for _, re := range webPatterns {
			if re.re.FindStringIndex(line) != nil {
				snippet := strings.TrimSpace(line)
				if len(snippet) > 200 {
					snippet = snippet[:200] + "…"
				}
				return "line:" + strconv.Itoa(i+1) + " " + snippet +
					" rules:" + strings.Join(matched, ",") +
					" entropy:" + strconv.FormatFloat(entropy, 'f', 2, 64)
			}
		}
	}
	if len(matched) > 0 {
		return "matched:" + strings.Join(matched, ",") +
			" entropy:" + strconv.FormatFloat(entropy, 'f', 2, 64)
	}
	return "entropy:" + strconv.FormatFloat(entropy, 'f', 2, 64)
}

func findWebWorkerPIDs(cfg *config.Config) map[int]struct{} {
	out := map[int]struct{}{}
	pids, err := procfs.Processes()
	if err != nil {
		return out
	}
	want := map[string]struct{}{}
	for _, n := range cfg.TargetProcessNames {
		want[strings.ToLower(n)] = struct{}{}
	}
	for _, pid := range pids {
		comm, err := procfs.Comm(pid)
		if err != nil {
			continue
		}
		if _, ok := want[strings.ToLower(strings.TrimSpace(comm))]; ok {
			out[pid] = struct{}{}
		}
	}
	return out
}

func treeHasShellChild(root int, _ *config.Config) bool {
	return walkChildrenForShell(root, 0, 4)
}

func walkChildrenForShell(pid int, depth, maxDepth int) bool {
	if depth > maxDepth {
		return false
	}
	kids, err := procfs.Children(pid)
	if err != nil {
		return false
	}
	for _, c := range kids {
		exe := procfs.ResolveExe(c)
		if exe != "" && shellChildPattern.MatchString(exe) {
			return true
		}
		argv, _ := procfs.Cmdline(c)
		if len(argv) > 0 && shellChildPattern.MatchString(argv[0]) {
			return true
		}
		if walkChildrenForShell(c, depth+1, maxDepth) {
			return true
		}
	}
	return false
}
