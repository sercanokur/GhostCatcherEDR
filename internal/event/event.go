package event

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// SchemaVersion bumps whenever the top-level event JSON shape changes.
//
//   1.0  - initial shape (rule_id, entity, signals, evidence).
//   1.1  - added process/file/network/container sub-documents and
//          correlation_id for cross-event correlation in SIEMs.
const SchemaVersion = "1.1"

type EntityType string

const (
	EntityFile    EntityType = "file"
	EntityProcess EntityType = "process"
	EntityUser    EntityType = "user"
	EntityCron    EntityType = "cron"
	EntityNetwork EntityType = "network"
)

type Entity struct {
	Type EntityType `json:"type"`
	ID   string     `json:"id"`
	Path string     `json:"path,omitempty"`
	User string     `json:"user,omitempty"`
}

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// ProcessContext is the optional per-event process snapshot; populated by
// detectors that have a pid.
type ProcessContext struct {
	PID        int      `json:"pid,omitempty"`
	PPID       int      `json:"ppid,omitempty"`
	Comm       string   `json:"comm,omitempty"`
	Argv       []string `json:"argv,omitempty"`
	Exe        string   `json:"exe,omitempty"`
	UID        int      `json:"uid,omitempty"`
	EUID       int      `json:"euid,omitempty"`
	AncestorComms []string `json:"ancestor_comms,omitempty"`
}

// FileContext is the optional per-event file snapshot; populated by
// file-centric detectors (web, integrity, persistence-file).
type FileContext struct {
	Path      string `json:"path,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	MD5       string `json:"md5,omitempty"`
	Size      int64  `json:"size,omitempty"`
	OwnerUID  uint32 `json:"owner_uid,omitempty"`
	Mode      string `json:"mode,omitempty"`
	MtimeUTC  string `json:"mtime_utc,omitempty"`
	SetUID    bool   `json:"setuid,omitempty"`
	SetGID    bool   `json:"setgid,omitempty"`
}

// NetworkContext is populated by the network sensor and by any other
// detector that knows a remote peer (e.g. curl in a cron line resolved via
// egress correlation).
type NetworkContext struct {
	Proto      string `json:"proto,omitempty"`
	LocalIP    string `json:"local_ip,omitempty"`
	LocalPort  int    `json:"local_port,omitempty"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	Direction  string `json:"direction,omitempty"` // inbound|outbound|listen
}

// ContainerContext classifies the agent's view of the workload. All fields
// are best-effort; non-containerized processes leave them empty.
type ContainerContext struct {
	Runtime string `json:"runtime,omitempty"` // docker|containerd|cri-o|k8s|lxc
	ID      string `json:"id,omitempty"`      // short id extracted from cgroup path
	PodUID  string `json:"pod_uid,omitempty"`
}

// Event is the stable JSON contract for all detectors.
type Event struct {
	SchemaVersion   string   `json:"schema_version"`
	AgentVersion    string   `json:"agent_version"`
	Timestamp       time.Time `json:"timestamp"`
	RuleID          string    `json:"rule_id"`
	RulePackVersion string    `json:"rule_pack_version"`
	TechniqueIDs    []string  `json:"technique_id"`
	Tactic          string    `json:"tactic,omitempty"`
	Confidence      int       `json:"confidence"`
	Severity        Severity  `json:"severity"`
	Entity          Entity    `json:"entity"`
	Signals         []string  `json:"signals"`
	DedupKey        string    `json:"dedup_key"`
	Evidence        string    `json:"evidence"`
	LearningOnly    bool      `json:"learning_only,omitempty"`

	// 1.1 additions. All pointer/optional so old consumers that only
	// read the top-level fields keep working.
	Process       *ProcessContext   `json:"process,omitempty"`
	File          *FileContext      `json:"file,omitempty"`
	Network       *NetworkContext   `json:"network,omitempty"`
	Container     *ContainerContext `json:"container,omitempty"`
	CorrelationID string            `json:"correlation_id,omitempty"`
	IOCMatches    []string          `json:"ioc_matches,omitempty"`
}

func (e *Event) NormalizeDedup() {
	if e.DedupKey != "" {
		return
	}
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s", e.RuleID, e.Entity.Path, e.Entity.ID)))
	e.DedupKey = hex.EncodeToString(h[:])
}

func (e Event) JSONLine() ([]byte, error) {
	return json.Marshal(e)
}
