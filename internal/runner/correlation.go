package runner

import (
	"sync"
	"time"

	"ghostcatcher/internal/event"
	"ghostcatcher/internal/rules"
)

// corrEntry records one past firing used for time-windowed correlation.
type corrEntry struct {
	ruleID string
	entity string
	when   time.Time
}

// correlator keeps a bounded ring of recent (rule_id, entity, time) tuples.
// When a new event arrives for a rule that declares `correlate:` peers, we
// check whether any of those peer rules also fired on the same entity
// within the declared window; if so, the new event is boosted.
type correlator struct {
	mu      sync.Mutex
	entries []corrEntry
	cap     int
}

func newCorrelator(cap int) *correlator {
	if cap <= 0 {
		cap = 1024
	}
	return &correlator{cap: cap}
}

func (c *correlator) add(ruleID, entity string, when time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, corrEntry{ruleID: ruleID, entity: entity, when: when})
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
	for _, en := range c.entries {
		if _, ok := peers[en.ruleID]; !ok {
			continue
		}
		if now.Sub(en.when) > win {
			continue
		}
		if entity != "" && en.entity != "" && en.entity != entity {
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
