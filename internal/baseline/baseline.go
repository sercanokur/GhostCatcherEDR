package baseline

import (
	"encoding/json"
	"os"
	"time"
)

const BaselineVersion = 1

// Snapshot is the frozen "known good" state after `baseline commit`.
//
// Fields were added incrementally; decoders MUST tolerate missing map keys
// (Load() initializes every map to empty when absent from the JSON).
type Snapshot struct {
	Version     int                      `json:"version"`
	CommittedAt time.Time                `json:"committed_at"`
	AuthKeys    map[string][]string      `json:"authorized_keys"`
	CronLines   map[string][]string      `json:"cron_lines"`
	WebFiles    map[string]WebFileRecord `json:"web_files"`
	LDPreload   []string                 `json:"ld_preload_values"`

	// PersistenceFiles is a generic path -> sha256 map used by the shellrc,
	// pam, sudoers, sshd, users, kmod, ldconf and systemd scanners so they
	// share a single storage format instead of each carrying its own.
	PersistenceFiles map[string]string `json:"persistence_files,omitempty"`

	// LoadedKernelModules is the set of module names present on the host at
	// commit time. Delta triggers KMOD_NEW events.
	LoadedKernelModules []string `json:"loaded_kernel_modules,omitempty"`

	// SUIDInventory and FileCapabilities track security-sensitive file bits
	// on $PATH-like directories. See integrity/suid.go and integrity/caps.go.
	SUIDInventory    map[string]string `json:"suid_inventory,omitempty"`
	FileCapabilities map[string]string `json:"file_capabilities,omitempty"`

	// ProcessAncestry stores `(parent_comm\x00child_comm)` strings observed
	// during the learning window. See rules/correlator for the usage.
	ProcessAncestry []string `json:"process_ancestry,omitempty"`

	// LoadedLibraries maps a watched process comm (e.g. "nginx") to the set
	// of .so paths loaded at commit; memorymaps uses this to flag unexpected
	// shared objects.
	LoadedLibraries map[string][]string `json:"loaded_libraries,omitempty"`
}

type WebFileRecord struct {
	SHA256 string    `json:"sha256"`
	Mtime  time.Time `json:"mtime"`
}

func EmptySnapshot() *Snapshot {
	return &Snapshot{
		Version:          BaselineVersion,
		AuthKeys:         make(map[string][]string),
		CronLines:        make(map[string][]string),
		WebFiles:         make(map[string]WebFileRecord),
		PersistenceFiles: make(map[string]string),
		SUIDInventory:    make(map[string]string),
		FileCapabilities: make(map[string]string),
		LoadedLibraries:  make(map[string][]string),
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
	if s.PersistenceFiles == nil {
		s.PersistenceFiles = make(map[string]string)
	}
	if s.SUIDInventory == nil {
		s.SUIDInventory = make(map[string]string)
	}
	if s.FileCapabilities == nil {
		s.FileCapabilities = make(map[string]string)
	}
	if s.LoadedLibraries == nil {
		s.LoadedLibraries = make(map[string][]string)
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
