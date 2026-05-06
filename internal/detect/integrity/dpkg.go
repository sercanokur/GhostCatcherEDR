package integrity

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/rules"
)

// scanDpkg verifies critical binaries against dpkg md5sums. Hashing opens
// the file once and pins it via fd for the lifetime of the read so an
// attacker cannot swap the file between Stat and ReadFile (TOCTOU).
func scanDpkg(cfg *config.Config, _ *baseline.Snapshot, pack *rules.Pack, agentVer string, now time.Time) []event.Event {
	var events []event.Event
	for _, abs := range cfg.IntegrityPaths {
		abs = filepath.Clean(abs)
		if r, err := filepath.EvalSymlinks(abs); err == nil {
			abs = filepath.Clean(r)
		}
		f, err := os.Open(abs)
		if err != nil {
			continue
		}
		st, err := f.Stat()
		if err != nil || st.IsDir() {
			_ = f.Close()
			continue
		}
		pkg, err := dpkgOwningPackage(abs)
		if err != nil || pkg == "" {
			_ = f.Close()
			continue
		}
		expected, err := md5FromDpkgInfo(pkg, abs)
		if err != nil || expected == "" {
			_ = f.Close()
			continue
		}
		sum, err := streamMD5Hex(f)
		_ = f.Close()
		if err != nil {
			continue
		}
		if strings.EqualFold(sum, expected) {
			continue
		}
		sigs := []string{"md5_mismatch_vs_dpkg", "package:" + pkg}
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
			Entity:          event.Entity{Type: event.EntityFile, ID: sum, Path: abs},
			Signals:         sigs,
			Evidence:        fmt.Sprintf("path=%s expected_md5=%s actual_md5=%s pkg=%s", abs, expected, sum, pkg),
			LearningOnly:    false,
		}
		ev.NormalizeDedup()
		events = append(events, ev)
	}
	return events
}

// streamMD5Hex computes the MD5 of the file while reading through an already
// opened descriptor so the data hashed is the data that was fd-pinned; avoids
// TOCTOU between Stat and ReadFile.
func streamMD5Hex(f *os.File) (string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func dpkgOwningPackage(absPath string) (string, error) {
	out, err := exec.Command("dpkg-query", "-S", absPath).Output()
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(out))
	for _, l := range strings.Split(line, "\n") {
		l = strings.TrimSpace(l)
		i := strings.IndexByte(l, ':')
		if i <= 0 {
			continue
		}
		return strings.TrimSpace(l[:i]), nil
	}
	return "", fmt.Errorf("no package")
}

func md5FromDpkgInfo(pkg, absPath string) (string, error) {
	infoPath := filepath.Join("/var/lib/dpkg/info", pkg+".md5sums")
	f, err := os.Open(infoPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	target := strings.TrimPrefix(filepath.Clean(absPath), "/")
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(parts[1], "./"), "/")
		rel = filepath.ToSlash(rel)
		tgt := filepath.ToSlash(target)
		if rel == tgt || rel == strings.TrimPrefix(tgt, "/") {
			return parts[0], nil
		}
		if "/"+rel == absPath || rel == strings.TrimPrefix(absPath, "/") {
			return parts[0], nil
		}
	}
	return "", fmt.Errorf("path not in md5sums")
}
