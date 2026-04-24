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

// High-priority patterns (plan: multi-pattern set without YARA for portability).
var webPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(eval|assert|create_function)\s*\(`),
	regexp.MustCompile(`(?i)\b(base64_decode|gzinflate|str_rot13)\s*\(`),
	regexp.MustCompile(`(?i)\b(shell_exec|passthru|system|exec|popen|proc_open)\s*\(`),
	regexp.MustCompile(`(?i)\$\_(GET|POST|REQUEST|COOKIE)\s*\[\s*['\"][^'\"]+['\"]\s*\]\s*\(`),
	regexp.MustCompile(`(?i)preg_replace\s*\([^)]*\/e['\"]`),
}

var shellChildPattern = regexp.MustCompile(`(?i)/(ba)?sh$|perl|python[0-9.]*$|php$`)

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
			if !stringsHasSuffixFold(path, ".php") && !stringsHasSuffixFold(path, ".phtml") && !stringsHasSuffixFold(path, ".jsp") {
				return nil
			}
			if pathAllowlisted(path, cfg.PathAllowlist) {
				return nil
			}
			st, err := d.Info()
			if err != nil {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			sum := sha256.Sum256(data)
			hash := hex.EncodeToString(sum[:])
			rec, inBase := snap.WebFiles[path]
			recent := time.Since(st.ModTime()) <= time.Duration(cfg.WebRecentDays)*24*time.Hour
			newOrChanged := !inBase || rec.SHA256 != hash

			matched := matchingPatterns(string(data))
			if len(matched) == 0 {
				return nil
			}
			sigs := []string{"suspicious_web_pattern:" + strings.Join(matched, ",")}
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

			// After baseline commit, "recent mtime" alone must not escalate (hash unchanged).
			high := len(matched) > 0 && (childSig || newOrChanged || (!snap.IsCommitted() && recent))
			if !high {
				conf, _ := rules.Score(pack, RuleWebShell, sigs)
				conf = min(conf, 50)
				ev := event.Event{
					SchemaVersion:   event.SchemaVersion,
					AgentVersion:    agentVer,
					Timestamp:       now,
					RuleID:          RuleWebShell,
					RulePackVersion: pack.Version,
					TechniqueIDs:    []string{"T1505.003"},
					Tactic:          "persistence",
					Confidence:      conf,
					Severity:        event.SeverityInfo,
					Entity:          event.Entity{Type: event.EntityFile, ID: hash, Path: path},
					Signals:         sigs,
					Evidence:        evidenceSnippet(string(data), matched),
					LearningOnly:    true,
				}
				ev.NormalizeDedup()
				events = append(events, ev)
				return nil
			}

			if childSig {
				sigs = append(sigs, "correlated_T1059")
			}
			conf, _ := rules.Score(pack, RuleWebShell, sigs)
			tech := []string{"T1505.003"}
			if childSig {
				tech = append(tech, "T1059.004")
			}
			ev := event.Event{
				SchemaVersion:   event.SchemaVersion,
				AgentVersion:    agentVer,
				Timestamp:       now,
				RuleID:          RuleWebShell,
				RulePackVersion: pack.Version,
				TechniqueIDs:    tech,
				Tactic:          "persistence",
				Confidence:      conf,
				Severity:        rules.SeverityFromConfidence(conf, learning),
				Entity:          event.Entity{Type: event.EntityFile, ID: hash, Path: path},
				Signals:         sigs,
				Evidence:        evidenceSnippet(string(data), matched),
				LearningOnly:    learning || conf < cfg.MinConfidenceAlert,
			}
			ev.NormalizeDedup()
			events = append(events, ev)
			return nil
		})
	}
	return events, nil
}

func stringsHasSuffixFold(s, suf string) bool {
	return len(s) >= len(suf) && strings.EqualFold(s[len(s)-len(suf):], suf)
}

func pathAllowlisted(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(path, filepath.Clean(p)) {
			return true
		}
	}
	return false
}

func matchingPatterns(content string) []string {
	var names []string
	for i, re := range webPatterns {
		if re.FindStringIndex(content) != nil {
			names = append(names, patternName(i))
		}
	}
	return names
}

func patternName(i int) string {
	names := []string{"dynamic_eval", "encoding_obfuscation", "php_exec_funcs", "user_input_call", "preg_replace_e"}
	if i < len(names) {
		return names[i]
	}
	return "pattern"
}

func evidenceSnippet(content string, matched []string) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		for _, re := range webPatterns {
			if re.FindStringIndex(line) != nil {
				snippet := strings.TrimSpace(line)
				if len(snippet) > 200 {
					snippet = snippet[:200] + "…"
				}
				return "line:" + strconv.Itoa(i+1) + " " + snippet + " rules:" + strings.Join(matched, ",")
			}
		}
	}
	return "matched:" + strings.Join(matched, ",")
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
