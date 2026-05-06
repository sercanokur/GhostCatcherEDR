package rules

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Pack is versioned rule metadata shipped with the agent. In addition to
// the original scoring knobs it now optionally carries a compiled boolean
// expression per rule, produced from the `expr` YAML field, which the
// runner can consult as a precondition before emitting.
type Pack struct {
	Version string `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

type Rule struct {
	ID          string   `yaml:"id"`
	Techniques  []string `yaml:"techniques"`
	Tactic      string   `yaml:"tactic"`
	MinSignals  int      `yaml:"min_signals"`
	BaseScore   int      `yaml:"base_score"`
	PerSignal   int      `yaml:"per_signal_bonus"`
	CapScore    int      `yaml:"cap_score"`
	Description string   `yaml:"description"`

	// Expr (optional) is a boolean expression that, when present, must
	// evaluate to true for an event to be alert-worthy. See expr.go.
	Expr string `yaml:"expr"`

	// Correlate (optional) links this rule to one or more other rule IDs
	// that must have fired within CorrelateWindow for this one to escalate.
	// Left empty for standalone rules.
	Correlate        []string `yaml:"correlate"`
	CorrelateWindow  string   `yaml:"correlate_window"`
	CorrelateBoost   int      `yaml:"correlate_boost"`

	compiled *Expr // cached, hydrated during LoadPack
}

// CompiledExpr returns the cached compiled expression (or a "true" default
// when none was specified). Never returns nil.
func (r Rule) CompiledExpr() *Expr {
	if r.compiled != nil {
		return r.compiled
	}
	e, _ := CompileExpr("")
	return e
}

// LoadPack reads a YAML rule pack, hydrates defaults, compiles expressions
// eagerly so load-time errors fail-fast, and returns the ready pack.
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
		if p.Rules[i].Expr != "" {
			e, err := CompileExpr(p.Rules[i].Expr)
			if err != nil {
				return nil, fmt.Errorf("rule %q: compile expr: %w", p.Rules[i].ID, err)
			}
			p.Rules[i].compiled = e
		}
	}
	return &p, nil
}

// ByID returns the rule with matching ID, and true when found.
func (p *Pack) ByID(id string) (Rule, bool) {
	for _, r := range p.Rules {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}

// Merge appends additional rules from extra into p. IDs that already exist
// in p are skipped so the user cannot accidentally shadow a built-in rule
// by dropping a malformed extra pack.
func (p *Pack) Merge(extra *Pack) {
	if extra == nil {
		return
	}
	have := map[string]struct{}{}
	for _, r := range p.Rules {
		have[r.ID] = struct{}{}
	}
	for _, r := range extra.Rules {
		if _, dup := have[r.ID]; dup {
			continue
		}
		p.Rules = append(p.Rules, r)
	}
}
