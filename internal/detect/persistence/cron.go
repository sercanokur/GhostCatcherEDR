package persistence

import (
	"bufio"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/rules"
)

// cronDirs and standaloneCronFiles enumerate every canonical Linux cron surface.
// Missing entries = blind spots for persistence; this list is intentionally
// broader than T1053.003 (cron only) to cover anacron and periodic drop-ins.
var (
	standaloneCronFiles = []string{
		"/etc/crontab",
		"/etc/anacrontab",
	}
	cronDirs = []string{
		"/etc/cron.d",
		"/etc/cron.hourly",
		"/etc/cron.daily",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
		"/var/spool/cron/crontabs",
		"/var/spool/cron", // RHEL/CentOS
		"/var/spool/anacron",
		"/var/spool/atjobs",
		"/var/spool/at",
		"/var/spool/cron/atjobs",
	}
)

// cronRiskTokens lists substrings that are near-certain red flags in a new
// cron line. Each entry is matched case-insensitively against the normalized
// (shell-unescaped) line AND against any base64-decoded payload discovered
// inside the line, so `bash -c 'base64 -d <<< ...'` cannot bypass it.
var cronRiskTokens = []string{
	// Remote fetch + pipe-to-shell tradecraft.
	"curl ", " wget ", "curl -s", "wget -q", "| bash", "|sh ", "| sh", "| /bin/", "| dash",
	// Shell one-liners.
	"bash -c", "/bin/bash -c", "/bin/sh -c", "dash -c", "zsh -c",
	// Decoders and interpreters piped into exec.
	"base64 -d", "base64 --decode", "openssl enc -", "xxd -r",
	"python -c", "python3 -c", "perl -e", "ruby -e", "php -r",
	// Reverse-shell and data-exfil primitives.
	"/dev/tcp/", "socat ", " nc -", " ncat ", " netcat ",
	// Classic persistence-ish helpers.
	"chmod +x", "chattr +i", "iptables -I", "eval ",
	// Direct URL invocation.
	"http://", "https://",
}

// argLikeRE strips quotes and balanced whitespace for a rough shell lex that
// normalizes `'ba''sh'` and `"b"ase"6"4` into `bash` / `base64` before token
// substring matching runs.
var argLikeRE = regexp.MustCompile(`['"]`)

// normalizeCronLine returns a best-effort shell-unescaped form of a cron
// command for substring-based risk scoring. It intentionally does NOT try
// to be a correct shell parser; it only collapses quoting tricks and
// decodes inline base64 payloads.
func normalizeCronLine(line string) string {
	low := strings.ToLower(line)
	low = argLikeRE.ReplaceAllString(low, "")
	low = strings.ReplaceAll(low, "\\\n", " ")
	low = recursiveBase64Decode(low, 3)
	return " " + low + " "
}

// recursiveBase64Decode finds base64 blobs in the string and appends the
// decoded text so token rules match through common `echo ... | base64 -d`
// or `<<< 'base64...'` patterns. Depth-bounded to avoid pathological input.
func recursiveBase64Decode(s string, depth int) string {
	if depth <= 0 {
		return s
	}
	out := s
	matches := base64BlobRE.FindAllString(s, -1)
	for _, m := range matches {
		if len(m) < 16 {
			continue
		}
		dec, err := base64.StdEncoding.DecodeString(m)
		if err != nil {
			continue
		}
		ds := string(dec)
		if !looksPrintable(ds) {
			continue
		}
		out += " " + recursiveBase64Decode(strings.ToLower(ds), depth-1)
	}
	return out
}

var base64BlobRE = regexp.MustCompile(`[A-Za-z0-9+/]{16,}={0,2}`)

func looksPrintable(s string) bool {
	if s == "" {
		return false
	}
	var printable int
	for _, r := range s {
		if r == '\n' || r == '\t' || (r >= 0x20 && r < 0x7f) {
			printable++
		}
	}
	return float64(printable)/float64(len(s)) > 0.8
}

// EvalCronLine is the public single-line entry point used by the `eval`
// subcommand. It returns true iff the line is deemed high-risk by the
// same token/base64 pipeline the periodic scanner uses.
func EvalCronLine(line string) bool {
	risk, _ := cronRisk(normalizeCronLine(line))
	return risk
}

// cronRisk reports whether a normalized line contains a high-risk token.
// It also returns the first matched token for evidence.
func cronRisk(normalized string) (bool, string) {
	for _, tok := range cronRiskTokens {
		if strings.Contains(normalized, tok) {
			return true, strings.TrimSpace(tok)
		}
	}
	return false, ""
}

// collectCronTargets returns every regular file under the canonical cron
// surfaces that actually exists. Missing files and non-dir entries are
// silently skipped so non-Linux test runs continue to work.
func collectCronTargets() []string {
	var files []string
	for _, f := range standaloneCronFiles {
		if st, err := os.Stat(f); err == nil && !st.IsDir() {
			files = append(files, f)
		}
	}
	for _, d := range cronDirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			files = append(files, filepath.Join(d, e.Name()))
		}
	}
	return files
}

func scanCron(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string, now time.Time) ([]event.Event, error) {
	var events []event.Event
	learning := cfg.LearningMode || !snap.IsCommitted()
	if cfg.FirstRunAllowAlerts {
		learning = cfg.LearningMode
	}

	for _, fpath := range collectCronTargets() {
		data, err := os.ReadFile(fpath)
		if err != nil {
			continue
		}
		baselineSet := map[string]struct{}{}
		for _, fp := range snap.CronLines[fpath] {
			baselineSet[fp] = struct{}{}
		}
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		lineNo := 0
		for sc.Scan() {
			lineNo++
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fp := cronLineFingerprint(fpath, line)
			if _, ok := baselineSet[fp]; ok {
				continue
			}
			normalized := normalizeCronLine(line)
			risk, tok := cronRisk(normalized)
			sigs := []string{"new_cron_line"}
			if risk {
				sigs = append(sigs, "high_risk_token:"+tok)
			}
			if strings.Contains(normalized, "base64") && strings.Contains(normalized, "-d") {
				sigs = append(sigs, "inline_base64_decoded")
			}
			ev := event.Event{
				SchemaVersion:   event.SchemaVersion,
				AgentVersion:    agentVer,
				Timestamp:       now,
				RuleID:          RuleCronHighRisk,
				RulePackVersion: pack.Version,
				TechniqueIDs:    []string{"T1053.003"},
				Tactic:          "persistence",
				Entity:          event.Entity{Type: event.EntityCron, ID: fp, Path: fpath},
				Signals:         sigs,
				Evidence:        truncate(line, 200),
			}
			conf, _ := rules.Score(pack, RuleCronHighRisk, sigs)
			if !risk {
				conf = minInt(conf, 40)
				ev.Confidence = conf
				ev.Severity = event.SeverityInfo
				ev.LearningOnly = true
			} else {
				ev.Confidence = conf
				ev.Severity = rules.SeverityFromConfidence(conf, learning)
				ev.LearningOnly = learning || conf < cfg.MinConfidenceAlert
			}
			ev.NormalizeDedup()
			events = append(events, ev)
		}
	}
	return events, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
