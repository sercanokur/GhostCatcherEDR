package baseline

import (
	"encoding/json"
	"os"
	"time"
)

const BaselineVersion = 1

// Snapshot is the frozen "known good" state after `baseline commit`.
type Snapshot struct {
	Version     int                              `json:"version"`
	CommittedAt time.Time                        `json:"committed_at"`
	AuthKeys    map[string][]string              `json:"authorized_keys"` // path -> ssh key fingerprints
	CronLines   map[string][]string                `json:"cron_lines"`      // file path -> line fingerprints
	WebFiles    map[string]WebFileRecord         `json:"web_files"`       // path -> hash + mtime
	LDPreload   []string                         `json:"ld_preload_values"` // allowed exact LD_PRELOAD values seen at commit
}

type WebFileRecord struct {
	SHA256 string    `json:"sha256"`
	Mtime  time.Time `json:"mtime"`
}

func EmptySnapshot() *Snapshot {
	return &Snapshot{
		Version:   BaselineVersion,
		AuthKeys:  make(map[string][]string),
		CronLines: make(map[string][]string),
		WebFiles:  make(map[string]WebFileRecord),
	}
}

func Load(path string) (*Snapshot, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return EmptySnapshot(), nil
		}
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if s.AuthKeys == nil {
		s.AuthKeys = make(map[string][]string)
	}
	if s.CronLines == nil {
		s.CronLines = make(map[string][]string)
	}
	if s.WebFiles == nil {
		s.WebFiles = make(map[string]WebFileRecord)
	}
	return &s, nil
}

func (s *Snapshot) Save(path string) error {
	tmp := path + ".tmp"
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Snapshot) IsCommitted() bool {
	return !s.CommittedAt.IsZero()
}
