package runner

import (
	"sync"
	"time"

	"ghostcatcher/internal/event"
	"ghostcatcher/internal/rules"
	"ghostcatcher/internal/taxonomy"
)

// corrEntry records one past firing used for time-windowed correlation.
type corrEntry struct {
	ruleID    string
	entity    string
	anchor    string
	confBand  string
	when      time.Time
}

// correlator keeps a bounded ring of recent firings and evaluates both
// pairwise rule-pack correlate directives and ordered bhv CHAIN-1…6.
type correlator struct {
	mu      sync.Mutex
	entries []corrEntry
	cap     int
	chains  []taxonomy.Chain
}

func newCorrelator(cap int) *correlator {
	if cap <= 0 {
		cap = 1024
	}
	return &correlator{cap: cap}
}

func (c *correlator) setChains(chains []taxonomy.Chain) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.chains = append([]taxonomy.Chain(nil), chains...)
}

func (c *correlator) add(ruleID, entity string, when time.Time) {
	c.addFull(ruleID, entity, "", "", when)
}

func (c *correlator) addFull(ruleID, entity, anchor, confBand string, when time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, corrEntry{
		ruleID: ruleID, entity: entity, anchor: anchor, confBand: confBand, when: when,
	})
	if len(c.entries) > c.cap {
		c.entries = c.entries[len(c.entries)-c.cap:]
	}
}

// matchBoost returns how many confidence points to add to e based on the
// rule pack's correlate directives. The caller is expected to already have
// computed facts for e. Returns 0 if nothing correlated.
func (c *correlator) matchBoost(e *event.Event, rule rules.Rule, now time.Time) int {
	if len(rule.Correlate) == 0 {
		return 0
	}
	win := parseDuration(rule.CorrelateWindow, 5*time.Minute)
	c.mu.Lock()
	defer c.mu.Unlock()
	peers := map[string]struct{}{}
	for _, id := range rule.Correlate {
		peers[id] = struct{}{}
	}
	entity := e.Entity.ID
	anchor := e.Anchor
	for _, en := range c.entries {
		if _, ok := peers[en.ruleID]; !ok {
			continue
		}
		if now.Sub(en.when) > win {
			continue
		}
		if anchor != "" && en.anchor != "" {
			if anchor != en.anchor {
				continue
			}
		} else if entity != "" && en.entity != "" && en.entity != entity {
			continue
		}
		boost := rule.CorrelateBoost
		if boost == 0 {
			boost = 10
		}
		return boost
	}
	return 0
}

// matchChain evaluates ordered bhv chains. On match it stamps ChainID /
// EvidenceLoss and returns a confidence boost (saturating toward 100).
func (c *correlator) matchChain(e *event.Event, now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	best := 0
	for _, ch := range c.chains {
		if boost, ok := c.evalChain(ch, e, now); ok && boost > best {
			best = boost
			e.ChainID = ch.ID
			if ch.Flag == "evidence_loss" {
				e.EvidenceLoss = true
			}
			if ch.Score == "CRITICAL" {
				e.Severity = event.SeverityCritical
			}
		}
	}
	return best
}

func (c *correlator) evalChain(ch taxonomy.Chain, e *event.Event, now time.Time) (int, bool) {
	if len(ch.Steps) == 0 {
		return 0, false
	}
	win := parseDuration(ch.Window, 30*time.Minute)
	// Current event must land in the last non-empty step (or any HIGH for CHAIN-6 step0 empty).
	lastIdx := len(ch.Steps) - 1
	if !stepMatches(ch.Steps[lastIdx], e.RuleID, e.ConfBand, lastIdx == 0 && len(ch.Steps[0]) == 0) {
		// Also allow current event to complete an intermediate progression:
		// walk steps so that each prior step has a matching past entry.
		return c.evalChainProgress(ch, e, now, win)
	}
	return c.evalChainProgress(ch, e, now, win)
}

func (c *correlator) evalChainProgress(ch taxonomy.Chain, e *event.Event, now time.Time, win time.Duration) (int, bool) {
	// Find which step the current event satisfies.
	curStep := -1
	for i, step := range ch.Steps {
		if stepMatches(step, e.RuleID, e.ConfBand, i == 0 && len(step) == 0) {
			curStep = i
			break
		}
	}
	if curStep < 0 {
		return 0, false
	}
	// Require prior steps to have fired (any-of within step) within window,
	// preferring same anchor when both sides have one.
	for s := 0; s < curStep; s++ {
		step := ch.Steps[s]
		if len(step) == 0 {
			// CHAIN-6: any HIGH band prior event
			if !c.anyHighInWindow(e.Anchor, now, win) {
				return 0, false
			}
			continue
		}
		if !c.anyRuleInWindow(step, e.Anchor, now, win) {
			return 0, false
		}
	}
	if curStep == 0 {
		return 0, false // need at least one prior step for a chain hit
	}
	return 25, true
}

func stepMatches(step []string, ruleID, confBand string, anyHigh bool) bool {
	if anyHigh || (len(step) == 0) {
		return confBand == event.ConfHigh || confBand == "HIGH"
	}
	for _, id := range step {
		if id == ruleID {
			return true
		}
	}
	return false
}

func (c *correlator) anyRuleInWindow(ids []string, anchor string, now time.Time, win time.Duration) bool {
	want := map[string]struct{}{}
	for _, id := range ids {
		want[id] = struct{}{}
	}
	for _, en := range c.entries {
		if now.Sub(en.when) > win {
			continue
		}
		if _, ok := want[en.ruleID]; !ok {
			continue
		}
		if anchor != "" && en.anchor != "" && anchor != en.anchor {
			continue
		}
		return true
	}
	return false
}

func (c *correlator) anyHighInWindow(anchor string, now time.Time, win time.Duration) bool {
	for _, en := range c.entries {
		if now.Sub(en.when) > win {
			continue
		}
		if en.confBand != event.ConfHigh && en.confBand != "HIGH" {
			continue
		}
		if anchor != "" && en.anchor != "" && anchor != en.anchor {
			continue
		}
		return true
	}
	return false
}

func parseDuration(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fallback
	}
	return d
}
