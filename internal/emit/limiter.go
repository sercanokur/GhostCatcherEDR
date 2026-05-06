// Package emit owns the downstream side of the pipeline: rate limiting
// events per rule, pluggable sinks, and a durable on-disk spool that
// survives brief sink outages.
package emit

import (
	"sync"
	"time"
)

// Limiter is a per-rule, sliding-window event cap. It exists because one
// noisy rule must never drown out the rest of the agent's telemetry or
// overrun the SIEM's ingest budget.
//
// A zero or negative `perMinute` disables rate limiting entirely.
type Limiter struct {
	mu        sync.Mutex
	perMinute int
	window    time.Duration
	hits      map[string][]time.Time
	dropped   map[string]int64
}

// NewLimiter builds a Limiter that allows `perMinute` events per rule
// id in any rolling 60-second window.
func NewLimiter(perMinute int) *Limiter {
	return &Limiter{
		perMinute: perMinute,
		window:    time.Minute,
		hits:      map[string][]time.Time{},
		dropped:   map[string]int64{},
	}
}

// Allow reports whether the caller should emit an event with ruleID now.
// Returns false when the rule has already hit its per-minute cap.
func (l *Limiter) Allow(ruleID string) bool {
	if l == nil || l.perMinute <= 0 {
		return true
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-l.window)
	buf := l.hits[ruleID]
	// trim aged entries
	i := 0
	for ; i < len(buf); i++ {
		if buf[i].After(cutoff) {
			break
		}
	}
	buf = buf[i:]
	if len(buf) >= l.perMinute {
		l.hits[ruleID] = buf
		l.dropped[ruleID]++
		return false
	}
	buf = append(buf, now)
	l.hits[ruleID] = buf
	return true
}

// Dropped returns the total drop count per rule since the limiter was
// created. Useful for periodic self-diagnostic events.
func (l *Limiter) Dropped() map[string]int64 {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[string]int64, len(l.dropped))
	for k, v := range l.dropped {
		out[k] = v
	}
	return out
}
