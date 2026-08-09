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
//	1.0  - initial shape (rule_id, entity, signals, evidence).
//	1.1  - added process/file/network/container sub-documents and
//	       correlation_id for cross-event correlation in SIEMs.
//	1.2  - kill_chain_phase, defense_layer, soc_escalate, response (OODA Act).
//	1.3  - bhv.md taxonomy: macro, micro, src, type, anchor, conf_band.
const SchemaVersion = "1.3"

// DefenseLayerEndpoint is the layer tag for events emitted by this agent.
const DefenseLayerEndpoint = "endpoint"

// Telemetry source labels from bhv.md field dictionary.
const (
	SrcEBPFExec  = "EBPF-EXEC"
	SrcEBPFNet   = "EBPF-NET"
	SrcEBPFFile  = "EBPF-FILE"
	SrcAudit     = "AUDIT"
	SrcFIM       = "FIM"
	SrcProcScan  = "PROCSCAN"
	SrcInventory = "INVENTORY"
)

// Detection type labels from bhv.md field dictionary.
const (
	TypeEvent = "EVENT"
	TypeDelta = "DELTA"
	TypeState = "STATE"
)

// Confidence band labels from bhv.md (standalone nano confidence).
const (
	ConfHigh   = "HIGH"
	ConfMedium = "MEDIUM"
	ConfLow    = "LOW"
)

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
	PID           int      `json:"pid,omitempty"`
	PPID          int      `json:"ppid,omitempty"`
	Comm          string   `json:"comm,omitempty"`
	Argv          []string `json:"argv,omitempty"`
	Exe           string   `json:"exe,omitempty"`
	UID           int      `json:"uid,omitempty"`
	EUID          int      `json:"euid,omitempty"`
	CapEff        string   `json:"cap_eff,omitempty"`
	AncestorComms []string `json:"ancestor_comms,omitempty"`
	Cgroup        string   `json:"cgroup,omitempty"`
	SystemdUnit   string   `json:"systemd_unit,omitempty"`
}

// FileContext is the optional per-event file snapshot; populated by
// file-centric detectors (web, integrity, persistence-file).
type FileContext struct {
	Path     string `json:"path,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	MD5      string `json:"md5,omitempty"`
	Size     int64  `json:"size,omitempty"`
	OwnerUID uint32 `json:"owner_uid,omitempty"`
	Mode     string `json:"mode,omitempty"`
	MtimeUTC string `json:"mtime_utc,omitempty"`
	SetUID   bool   `json:"setuid,omitempty"`
	SetGID   bool   `json:"setgid,omitempty"`
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

// ResponseContext records the OODA Act phase outcome (audit or enforce).
type ResponseContext struct {
	Action        string `json:"action,omitempty"` // alert_only|quarantine_file|kill_process|isolate_host
	Mode          string `json:"mode,omitempty"`   // audit|enforce
	Result        string `json:"result,omitempty"` // applied|skipped|denied|audit_logged
	Reason        string `json:"reason,omitempty"`
	Target        string `json:"target,omitempty"`          // pid, path, or host scope
	LoopLatencyMS int64  `json:"loop_latency_ms,omitempty"` // observe (sensor) -> act elapsed
}

// Event is the stable JSON contract for all detectors.
type Event struct {
	SchemaVersion   string    `json:"schema_version"`
	AgentVersion    string    `json:"agent_version"`
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

	// 1.2 additions — doctrine fields (OODA Act, Kill Chain, defense in depth).
	KillChainPhase string           `json:"kill_chain_phase,omitempty"`
	DefenseLayer   string           `json:"defense_layer,omitempty"`
	SOCEscalate    bool             `json:"soc_escalate,omitempty"`
	Response       *ResponseContext `json:"response,omitempty"`

	// 1.3 additions — bhv.md Macro→Micro→Nano taxonomy.
	Macro        string `json:"macro,omitempty"`         // e.g. M1, M2
	Micro        string `json:"micro,omitempty"`         // e.g. M1.1
	Src          string `json:"src,omitempty"`           // EBPF-EXEC|AUDIT|FIM|...
	Type         string `json:"type,omitempty"`          // EVENT|DELTA|STATE
	Anchor       string `json:"anchor,omitempty"`        // cgroup v2 path / systemd unit
	ConfBand     string `json:"conf_band,omitempty"`     // HIGH|MEDIUM|LOW
	EvidenceLoss bool   `json:"evidence_loss,omitempty"` // CHAIN-6 flag
	ChainID      string `json:"chain_id,omitempty"`      // CHAIN-1 … CHAIN-6
}

// FindingOpts carries taxonomy + scoring inputs for NewFinding.
type FindingOpts struct {
	RuleID          string
	RulePackVersion string
	AgentVersion    string
	Macro           string
	Micro           string
	Src             string
	Type            string
	Anchor          string
	ConfBand        string
	TechniqueIDs    []string
	Tactic          string
	Confidence      int
	Severity        Severity
	Entity          Entity
	Signals         []string
	Evidence        string
	LearningOnly    bool
	Process         *ProcessContext
	File            *FileContext
	Network         *NetworkContext
}

// NewFinding builds a schema 1.3 event with taxonomy fields set.
func NewFinding(opts FindingOpts) Event {
	now := time.Now().UTC()
	ev := Event{
		SchemaVersion:   SchemaVersion,
		AgentVersion:    opts.AgentVersion,
		Timestamp:       now,
		RuleID:          opts.RuleID,
		RulePackVersion: opts.RulePackVersion,
		TechniqueIDs:    opts.TechniqueIDs,
		Tactic:          opts.Tactic,
		Confidence:      opts.Confidence,
		Severity:        opts.Severity,
		Entity:          opts.Entity,
		Signals:         opts.Signals,
		Evidence:        opts.Evidence,
		LearningOnly:    opts.LearningOnly,
		Process:         opts.Process,
		File:            opts.File,
		Network:         opts.Network,
		Macro:           opts.Macro,
		Micro:           opts.Micro,
		Src:             opts.Src,
		Type:            opts.Type,
		Anchor:          opts.Anchor,
		ConfBand:        opts.ConfBand,
		DefenseLayer:    DefenseLayerEndpoint,
	}
	if ev.Anchor == "" && opts.Process != nil {
		if opts.Process.SystemdUnit != "" {
			ev.Anchor = opts.Process.SystemdUnit
		} else if opts.Process.Cgroup != "" {
			ev.Anchor = opts.Process.Cgroup
		}
	}
	ev.NormalizeDedup()
	return ev
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
