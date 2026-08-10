package web

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ghostcatcher/internal/anchor"
	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/budget"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/rules"
	"ghostcatcher/internal/sensor"
)

const (
	RuleDocrootExecWrite = "WEB_DOCROOT_EXEC_WRITE"
	RuleUploadDirExec    = "WEB_UPLOAD_DIR_EXEC"
	RuleAppFileTamper    = "WEB_APP_FILE_TAMPER"
)

var interpretableExt = map[string]struct{}{
	".php": {}, ".jsp": {}, ".jspx": {}, ".phar": {}, ".aspx": {},
	".py": {}, ".cgi": {}, ".phtml": {},
}

var uploadDirHints = []string{"uploads", "tmp", "cache", "temp", "upload"}

// RouteDocrootWrite fires when a web-cgroup process writes an interpretable file under a docroot.
func RouteDocrootWrite(cfg *config.Config, pack *rules.Pack, agentVer string, ev sensor.Event) (event.Event, bool) {
	path := strings.TrimSpace(ev.Path)
	if path == "" {
		path = strings.TrimSpace(ev.Extra["path"])
	}
	if path == "" {
		return event.Event{}, false
	}
	ext := strings.ToLower(filepath.Ext(path))
	if _, ok := interpretableExt[ext]; !ok {
		return event.Event{}, false
	}
	if !underDocroot(path, cfg.DocumentRoots) {
		return event.Event{}, false
	}
	ainfo := anchor.FromPID(ev.PID)
	if !anchor.IsWatchedUnit(ainfo.SystemdUnit, cfg.WatchedUnits) {
		// Fall back: still emit if path is under docroot (writer may be PHP-FPM child).
		if ainfo.SystemdUnit == "" {
			return event.Event{}, false
		}
	}
	ruleID := RuleDocrootExecWrite
	sig := "web_docroot_exec_write"
	if inUploadDir(path) {
		ruleID = RuleUploadDirExec
		sig = "web_upload_dir_exec"
	}
	sigs := []string{sig, "path:" + path, "comm:" + ev.Comm}
	conf, _ := rules.Score(pack, ruleID, sigs)
	if conf < 80 {
		conf = 80
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
		Entity:          event.Entity{Type: event.EntityFile, Path: path, ID: path},
		Signals:         sigs,
		Evidence:        path,
		Src:             event.SrcAudit,
		Type:            event.TypeEvent,
		Anchor:          ainfo.Anchor,
		ConfBand:        event.ConfHigh,
	}
	out.NormalizeDedup()
	return out, true
}

// ScanUploadDirs looks for new interpretable files in upload/tmp/cache dirs under docroots.
func ScanUploadDirs(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string) ([]event.Event, error) {
	var out []event.Event
	now := time.Now().UTC()
	learning := cfg.LearningMode || !snap.IsCommitted()
	if cfg.FirstRunAllowAlerts {
		learning = cfg.LearningMode
	}
	for _, root := range cfg.DocumentRoots {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if _, ok := interpretableExt[ext]; !ok {
				return nil
			}
			if !inUploadDir(path) {
				return nil
			}
			if rec, ok := snap.WebFiles[path]; ok {
				if baselineMetaMatches(info, rec) {
					return nil
				}
				sum := fileSHA(path)
				if sum != "" && rec.SHA256 == sum {
					return nil
				}
			}
			sigs := []string{"web_upload_dir_exec", "path:" + path}
			conf, _ := rules.Score(pack, RuleUploadDirExec, sigs)
			if conf < 80 {
				conf = 80
			}
			ev := event.Event{
				SchemaVersion:   event.SchemaVersion,
				AgentVersion:    agentVer,
				Timestamp:       now,
				RuleID:          RuleUploadDirExec,
				RulePackVersion: pack.Version,
				Confidence:      conf,
				Severity:        rules.SeverityFromConfidence(conf, learning),
				Entity:          event.Entity{Type: event.EntityFile, Path: path, ID: path},
				Signals:         sigs,
				Evidence:        path,
				LearningOnly:    learning || conf < cfg.MinConfidenceAlert,
				Src:             event.SrcFIM,
				Type:            event.TypeDelta,
				ConfBand:        event.ConfHigh,
			}
			ev.NormalizeDedup()
			out = append(out, ev)
			return nil
		})
	}
	return out, nil
}

// ScanAppTamper emits WEB_APP_FILE_TAMPER for baseline web files whose hash changed.
func ScanAppTamper(cfg *config.Config, snap *baseline.Snapshot, pack *rules.Pack, agentVer string) ([]event.Event, error) {
	if !snap.IsCommitted() {
		return nil, nil
	}
	var out []event.Event
	now := time.Now().UTC()
	learning := cfg.LearningMode
	for path, rec := range snap.WebFiles {
		st, err := os.Stat(path)
		if err != nil {
			continue
		}
		if baselineMetaMatches(st, rec) {
			continue
		}
		sum := fileSHA(path)
		if sum == "" || sum == rec.SHA256 {
			continue
		}
		sigs := []string{"web_app_file_tamper", "path:" + path}
		conf, _ := rules.Score(pack, RuleAppFileTamper, sigs)
		if conf < 60 {
			conf = 60
		}
		ev := event.Event{
			SchemaVersion:   event.SchemaVersion,
			AgentVersion:    agentVer,
			Timestamp:       now,
			RuleID:          RuleAppFileTamper,
			RulePackVersion: pack.Version,
			Confidence:      conf,
			Severity:        rules.SeverityFromConfidence(conf, learning),
			Entity:          event.Entity{Type: event.EntityFile, Path: path, ID: sum},
			Signals:         sigs,
			Evidence:        "hash changed vs baseline",
			LearningOnly:    learning || conf < cfg.MinConfidenceAlert,
			Src:             event.SrcInventory,
			Type:            event.TypeDelta,
			ConfBand:        event.ConfMedium,
		}
		ev.NormalizeDedup()
		out = append(out, ev)
	}
	return out, nil
}

func underDocroot(path string, roots []string) bool {
	clean := filepath.Clean(path)
	for _, r := range roots {
		r = filepath.Clean(r)
		if r != "" && (clean == r || strings.HasPrefix(clean, r+string(os.PathSeparator))) {
			return true
		}
	}
	return false
}

func inUploadDir(path string) bool {
	parts := strings.Split(strings.ToLower(filepath.ToSlash(path)), "/")
	for _, p := range parts {
		for _, h := range uploadDirHints {
			if p == h {
				return true
			}
		}
	}
	return false
}

func fileSHA(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	budget.AddHashBytes(int64(len(b)))
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
