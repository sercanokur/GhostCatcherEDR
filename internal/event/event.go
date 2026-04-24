package event

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

const SchemaVersion = "1.0"

type EntityType string

const (
	EntityFile    EntityType = "file"
	EntityProcess EntityType = "process"
	EntityUser    EntityType = "user"
	EntityCron    EntityType = "cron"
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

// Event is the stable JSON contract for all detectors.
type Event struct {
	SchemaVersion   string     `json:"schema_version"`
	AgentVersion    string     `json:"agent_version"`
	Timestamp       time.Time  `json:"timestamp"`
	RuleID          string     `json:"rule_id"`
	RulePackVersion string     `json:"rule_pack_version"`
	TechniqueIDs    []string   `json:"technique_id"`
	Tactic          string     `json:"tactic,omitempty"`
	Confidence      int        `json:"confidence"`
	Severity        Severity   `json:"severity"`
	Entity          Entity     `json:"entity"`
	Signals         []string   `json:"signals"`
	DedupKey        string     `json:"dedup_key"`
	Evidence        string     `json:"evidence"`
	LearningOnly    bool       `json:"learning_only,omitempty"`
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
