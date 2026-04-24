package rules

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Pack is versioned rule metadata shipped with the agent.
type Pack struct {
	Version string `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

type Rule struct {
	ID           string   `yaml:"id"`
	Techniques   []string `yaml:"techniques"`
	Tactic       string   `yaml:"tactic"`
	MinSignals   int      `yaml:"min_signals"`
	BaseScore    int      `yaml:"base_score"`
	PerSignal    int      `yaml:"per_signal_bonus"`
	CapScore     int      `yaml:"cap_score"`
	Description  string   `yaml:"description"`
}

func LoadPack(path string) (*Pack, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Pack
	if err := yaml.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	if p.Version == "" {
		p.Version = "0.0.0"
	}
	for i := range p.Rules {
		if p.Rules[i].CapScore == 0 {
			p.Rules[i].CapScore = 100
		}
		if p.Rules[i].MinSignals == 0 {
			p.Rules[i].MinSignals = 1
		}
		if p.Rules[i].PerSignal == 0 {
			p.Rules[i].PerSignal = 15
		}
	}
	return &p, nil
}

func (p *Pack) ByID(id string) (Rule, bool) {
	for _, r := range p.Rules {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}
