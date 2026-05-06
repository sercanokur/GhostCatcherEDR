package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/rules"
)

// suidScanDirs are the directories walked when enumerating SUID/SGID binaries.
// Order matters only for deterministic output.
var suidScanDirs = []string{
	"/bin", "/sbin", "/usr/bin", "/usr/sbin",
	"/usr/local/bin", "/usr/local/sbin",
	"/lib", "/usr/lib", "/lib64", "/usr/lib64",
	"/usr/libexec",
	"/opt",
}

// scanSUID walks every directory above looking for files with setuid or
// setgid bits. A path hashed at baseline is compared against the current
// hash; new paths, removed paths, or hash mismatches all emit events.
//
// Open-read-hash is done with a pinned descriptor so the file that is
// evaluated is the file that was opened (TOCTOU-safe).
func scanSUID(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string, now time.Time) []event.Event {
	learning := cfg.LearningMode || !snap.IsCommitted()
	if cfg.FirstRunAllowAlerts {
		learning = cfg.LearningMode
	}
	current := enumerateSUIDBinaries()
	var events []event.Event

	baseMap := snap.SUIDInventory
	if baseMap == nil {
		baseMap = map[string]string{}
	}

	// Additions and hash mismatches.
	for path, hash := range current {
		prev, ok := baseMap[path]
		if ok && prev == hash {
			continue
		}
		sigs := []string{"suid_binary_present"}
		if !ok {
			sigs = append(sigs, "new_suid_binary")
		} else {
			sigs = append(sigs, "suid_binary_hash_changed")
		}
		if !looksLikePackagedBinary(path) {
			sigs = append(sigs, "suid_in_world_writable_path")
		}
		conf, _ := rules.Score(pack, RuleSUIDAnomaly, sigs)
		if contains(sigs, "new_suid_binary") && conf < 90 {
			conf = 90
		}
		ev := event.Event{
			SchemaVersion:   event.SchemaVersion,
			AgentVersion:    agentVer,
			Timestamp:       now,
			RuleID:          RuleSUIDAnomaly,
			RulePackVersion: pack.Version,
			TechniqueIDs:    []string{"T1548.001"},
			Tactic:          "privilege-escalation",
			Confidence:      conf,
			Severity:        rules.SeverityFromConfidence(conf, learning),
			Entity:          event.Entity{Type: event.EntityFile, ID: hash, Path: path},
			Signals:         sigs,
			Evidence:        fmt.Sprintf("path=%s sha256=%s", path, hash),
			LearningOnly:    learning || conf < cfg.MinConfidenceAlert,
		}
		ev.NormalizeDedup()
		events = append(events, ev)
	}
	// Removals (SUID bit cleared or file deleted) are emitted as INFO -
	// useful for forensic timelines but not alert-worthy on their own.
	if snap.IsCommitted() {
		for path := range baseMap {
			if _, still := current[path]; still {
				continue
			}
			ev := event.Event{
				SchemaVersion:   event.SchemaVersion,
				AgentVersion:    agentVer,
				Timestamp:       now,
				RuleID:          RuleSUIDAnomaly,
				RulePackVersion: pack.Version,
				TechniqueIDs:    []string{"T1548.001"},
				Tactic:          "privilege-escalation",
				Confidence:      40,
				Severity:        event.SeverityInfo,
				Entity:          event.Entity{Type: event.EntityFile, ID: "removed:" + path, Path: path},
				Signals:         []string{"suid_binary_removed"},
				Evidence:        "SUID binary no longer present",
				LearningOnly:    true,
			}
			ev.NormalizeDedup()
			events = append(events, ev)
		}
	}
	return events
}

// enumerateSUIDBinaries returns a path -> sha256 map for every file with
// the setuid or setgid bit set under suidScanDirs.
func enumerateSUIDBinaries() map[string]string {
	out := map[string]string{}
	for _, dir := range suidScanDirs {
		st, err := os.Stat(dir)
		if err != nil || !st.IsDir() {
			continue
		}
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if info.Mode()&(os.ModeSetuid|os.ModeSetgid) == 0 {
				return nil
			}
			h, err := hashFilePinned(path)
			if err != nil {
				return nil
			}
			out[path] = h
			return nil
		})
	}
	return out
}

// hashFilePinned opens the file once and hashes the exact bytes the
// descriptor sees, avoiding TOCTOU between Stat and ReadFile.
func hashFilePinned(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// looksLikePackagedBinary is a conservative filter: paths under the well-known
// distro-owned directories are "packaged"; anything under /tmp, /home, /dev/shm
// etc. is world-writable and always suspicious when SUID.
func looksLikePackagedBinary(path string) bool {
	for _, good := range []string{"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/usr/lib/", "/lib/"} {
		if strings.HasPrefix(path, good) {
			return true
		}
	}
	return false
}

// BuildBaselineSUID captures the current SUID inventory into the snapshot.
func BuildBaselineSUID(_ *config.Config, snap *baseline.Snapshot) error {
	snap.SUIDInventory = enumerateSUIDBinaries()
	return nil
}

func contains(h []string, needle string) bool {
	for _, x := range h {
		if x == needle {
			return true
		}
	}
	return false
}
