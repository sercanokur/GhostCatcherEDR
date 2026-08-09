package privesc

import (
	"sync"
	"time"
)

// ProcessKey uniquely identifies a process instance (PID reuse safe).
type ProcessKey struct {
	PID       int
	StartTime uint64
}

// CredState is a compact credential/path snapshot of a running process.
type CredState struct {
	UID       int
	EUID      int
	CapEff    string
	Comm      string
	Exe       string
	PPID      int
	Ancestors []string
	Container string // runtime label if any (docker|k8s|...)
	SeenAt    time.Time
}

// Transition describes a non-root → privileged credential jump on the
// same process instance.
type Transition struct {
	Key      ProcessKey
	Prev     CredState
	Curr     CredState
	Kind     string // euid_root | capeff_full
	SeenAt   time.Time
}

// Tracker remembers the last credential state per process instance and
// emits transitions. First observation never alerts; only subsequent
// observations of the same PID+starttime can.
type Tracker struct {
	mu      sync.Mutex
	procs   map[ProcessKey]tracked
	maxSize int
}

type tracked struct {
	state   CredState
	alerted bool
}

// NewTracker returns an empty credential tracker. maxSize bounds memory;
// when exceeded, oldest entries are pruned opportunistically on Observe.
func NewTracker(maxSize int) *Tracker {
	if maxSize <= 0 {
		maxSize = 8192
	}
	return &Tracker{
		procs:   make(map[ProcessKey]tracked),
		maxSize: maxSize,
	}
}

// Observe records curr for key. If this instance previously looked
// unprivileged and now appears rooted (euid==0) or suddenly holds
// root-equivalent CapEff, a Transition is returned (at most once per
// instance unless ResetAlert is called in tests).
func (t *Tracker) Observe(key ProcessKey, curr CredState) *Transition {
	if key.PID <= 0 {
		return nil
	}
	if curr.SeenAt.IsZero() {
		curr.SeenAt = time.Now().UTC()
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	prev, ok := t.procs[key]
	if !ok {
		if len(t.procs) >= t.maxSize {
			t.pruneLocked(curr.SeenAt)
		}
		t.procs[key] = tracked{state: curr}
		return nil
	}

	if prev.alerted {
		// Keep state fresh but do not re-alert.
		t.procs[key] = tracked{state: curr, alerted: true}
		return nil
	}

	kind := transitionKind(prev.state, curr)
	t.procs[key] = tracked{state: curr, alerted: kind != ""}
	if kind == "" {
		return nil
	}
	return &Transition{
		Key:    key,
		Prev:   prev.state,
		Curr:   curr,
		Kind:   kind,
		SeenAt: curr.SeenAt,
	}
}

// Forget removes key (e.g. process exited). Safe if absent.
func (t *Tracker) Forget(key ProcessKey) {
	t.mu.Lock()
	delete(t.procs, key)
	t.mu.Unlock()
}

// RetainOnly drops every key not present in live. Used after a full
// /proc sweep so exited PIDs do not grow the map forever.
func (t *Tracker) RetainOnly(live map[ProcessKey]struct{}) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k := range t.procs {
		if _, ok := live[k]; !ok {
			delete(t.procs, k)
		}
	}
}

// Len returns tracked process count (tests / metrics).
func (t *Tracker) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.procs)
}

func (t *Tracker) pruneLocked(now time.Time) {
	// Drop anything older than 10 minutes first; if still over capacity
	// drop arbitrary extras until under the soft limit.
	cutoff := now.Add(-10 * time.Minute)
	for k, v := range t.procs {
		if v.state.SeenAt.Before(cutoff) {
			delete(t.procs, k)
		}
	}
	for k := range t.procs {
		if len(t.procs) < t.maxSize*3/4 {
			return
		}
		delete(t.procs, k)
	}
}

func transitionKind(prev, curr CredState) string {
	wasUnpriv := prev.UID != 0 && prev.EUID != 0
	if !wasUnpriv {
		return ""
	}
	if curr.EUID == 0 {
		return "euid_root"
	}
	if !capLooksFull(prev.CapEff) && capLooksFull(curr.CapEff) {
		return "capeff_full"
	}
	return ""
}

// capLooksFull matches the memorymaps heuristic: a long hex CapEff with
// many bits set (typical "root-equivalent" effective set).
func capLooksFull(capEff string) bool {
	v := trimLeftZeros(capEff)
	return len(v) >= 10
}

func trimLeftZeros(s string) string {
	i := 0
	for i < len(s) && (s[i] == '0' || s[i] == ' ') {
		i++
	}
	out := s[i:]
	if out == "" {
		return "0"
	}
	return out
}
