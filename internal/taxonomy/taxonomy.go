// Package taxonomy loads bhv.md Macro→Micro→Nano mapping metadata and
// applies it to events / rule packs.
package taxonomy

import (
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v3"

	"ghostcatcher/internal/event"
)

// Nano is one row from configs/mapping.yaml.
type Nano struct {
	ID         string   `yaml:"id"`
	Macro      string   `yaml:"macro"`
	Micro      string   `yaml:"micro"`
	Src        string   `yaml:"src"`
	Type       string   `yaml:"type"`
	Conf       string   `yaml:"conf"`
	Techniques []string `yaml:"techniques"`
	Tactic     string   `yaml:"tactic"`
	FP         string   `yaml:"fp"`
	Desc       string   `yaml:"desc"`
}

// Chain is an ordered correlation chain (CHAIN-1 … CHAIN-6).
type Chain struct {
	ID       string     `yaml:"id"`
	Window   string     `yaml:"window"`
	Score    string     `yaml:"score"` // CRITICAL
	Flag     string     `yaml:"flag"`  // e.g. evidence_loss
	Steps    [][]string `yaml:"steps"` // ordered groups; any-of within a group
}

// Mapping is the full bhv catalog file.
type Mapping struct {
	Version string  `yaml:"version"`
	Nanos   []Nano  `yaml:"nanos"`
	Chains  []Chain `yaml:"chains"`

	byID map[string]Nano
}

var (
	globalMu sync.RWMutex
	global   *Mapping
)

// Load reads mapping.yaml and indexes nanos by ID.
func Load(path string) (*Mapping, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Mapping
	if err := yaml.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	m.byID = make(map[string]Nano, len(m.Nanos))
	for _, n := range m.Nanos {
		if n.ID == "" {
			continue
		}
		m.byID[n.ID] = n
	}
	return &m, nil
}

// SetGlobal stores the process-wide mapping used by Apply.
func SetGlobal(m *Mapping) {
	globalMu.Lock()
	defer globalMu.Unlock()
	global = m
}

// Global returns the process-wide mapping (may be nil).
func Global() *Mapping {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return global
}

// Lookup returns nano metadata by rule/nano ID.
func (m *Mapping) Lookup(id string) (Nano, bool) {
	if m == nil {
		return Nano{}, false
	}
	n, ok := m.byID[id]
	return n, ok
}

// Apply fills taxonomy fields on e from the mapping for e.RuleID.
// Existing non-empty fields on e are preserved.
func Apply(e *event.Event) {
	m := Global()
	if m == nil || e == nil {
		return
	}
	n, ok := m.Lookup(e.RuleID)
	if !ok {
		return
	}
	if e.Macro == "" {
		e.Macro = n.Macro
	}
	if e.Micro == "" {
		e.Micro = n.Micro
	}
	if e.Src == "" {
		e.Src = n.Src
	}
	if e.Type == "" {
		e.Type = n.Type
	}
	if e.ConfBand == "" {
		e.ConfBand = n.Conf
	}
	if len(e.TechniqueIDs) == 0 && len(n.Techniques) > 0 {
		e.TechniqueIDs = append([]string{}, n.Techniques...)
	}
	if e.Tactic == "" {
		e.Tactic = n.Tactic
	}
}

// MustHave reports a clear error when a required nano is missing (tests/CI).
func (m *Mapping) MustHave(ids ...string) error {
	for _, id := range ids {
		if _, ok := m.Lookup(id); !ok {
			return fmt.Errorf("mapping missing nano %q", id)
		}
	}
	return nil
}
