package main

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

type stepStatus string

const (
	statusIdle     stepStatus = "idle"
	statusRunning  stepStatus = "running"
	statusDetected stepStatus = "detected"
	statusMissed   stepStatus = "missed"
	statusOK       stepStatus = "ok" // reset / no ES rule
	statusError    stepStatus = "error"
)

type StepDef struct {
	ID          string   `json:"id"`
	Index       int      `json:"index"`
	Group       string   `json:"group"`
	Title       string   `json:"title"`
	Narration   string   `json:"narration"`
	RuleIDs     []string `json:"rule_ids"`
	RemoteCmd   string   `json:"-"`
	WaitSecs    int      `json:"-"`
	ExpectRules bool     `json:"-"`
}

type StepState struct {
	StepDef
	Status    stepStatus `json:"status"`
	Log       string     `json:"log,omitempty"`
	Error     string     `json:"error,omitempty"`
	Evidence  []Evidence `json:"evidence,omitempty"`
	UpdatedAt string     `json:"updated_at,omitempty"`
}

type demoEngine struct {
	mu     sync.Mutex
	ssh    *sshClient
	term   *termHub
	steps  []StepState
	busy   bool
	target string
}

func newEngine(ssh *sshClient, term *termHub, target string) *demoEngine {
	defs := allStepDefs()
	steps := make([]StepState, len(defs))
	for i, d := range defs {
		steps[i] = StepState{StepDef: d, Status: statusIdle}
	}
	return &demoEngine{ssh: ssh, term: term, steps: steps, target: target}
}

func (e *demoEngine) snapshot() []StepState {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]StepState, len(e.steps))
	copy(out, e.steps)
	return out
}

func (e *demoEngine) runStep(id string) (StepState, error) {
	e.mu.Lock()
	if e.busy {
		e.mu.Unlock()
		return StepState{}, fmt.Errorf("another step is already running")
	}
	idx := -1
	for i := range e.steps {
		if e.steps[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		e.mu.Unlock()
		return StepState{}, fmt.Errorf("unknown step %q", id)
	}
	e.busy = true
	e.steps[idx].Status = statusRunning
	e.steps[idx].Error = ""
	e.steps[idx].Log = ""
	e.steps[idx].Evidence = nil
	e.steps[idx].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	cmd := e.steps[idx].RemoteCmd
	wait := e.steps[idx].WaitSecs
	rules := append([]string(nil), e.steps[idx].RuleIDs...)
	expect := e.steps[idx].ExpectRules
	title := e.steps[idx].Title
	e.mu.Unlock()

	defer func() {
		e.mu.Lock()
		e.busy = false
		e.mu.Unlock()
	}()

	e.term.Printf("meta", "")
	e.term.Printf("meta", "═══ %s ═══", title)
	e.term.Printf("cmd", "root@victim# %s", cmd)

	var before map[string]int
	if expect {
		e.term.Printf("meta", "snapshot ES counts before trigger…")
		before = e.esCounts(rules)
		for _, r := range rules {
			e.term.Printf("meta", "  %s count=%d", r, before[r])
		}
	}

	tw := &termWriter{hub: e.term, kind: "out"}
	out, err := e.ssh.RunStream(cmd, tw)
	tw.Flush()
	e.mu.Lock()
	e.steps[idx].Log = trim(out, 4000)
	e.mu.Unlock()

	if err != nil {
		e.term.Printf("err", "exit: %v", err)
		e.mu.Lock()
		e.steps[idx].Status = statusError
		e.steps[idx].Error = err.Error() + "\n" + firstLine(out)
		e.steps[idx].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		st := e.steps[idx]
		e.mu.Unlock()
		return st, err
	}
	e.term.Printf("meta", "command finished (exit 0)")

	if !expect {
		e.term.Printf("meta", "lab artifacts cleared — ready for next act")
		e.mu.Lock()
		e.steps[idx].Status = statusOK
		e.steps[idx].Evidence = []Evidence{{
			Detected: true,
			Title:    "Lab reset",
			Summary:  "Kill-chain artifacts cleared. Ready for a fresh run.",
			Bullets:  []string{"Cleared webshell drops under docker/rce", "Restored ld.so.preload / lab SSH keys if present"},
		}}
		e.steps[idx].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		st := e.steps[idx]
		e.mu.Unlock()
		return st, nil
	}

	e.term.Printf("meta", "waiting for GhostCatcher → Elasticsearch alerts…")
	evs := e.waitEvidence(rules, before, wait)
	all := true
	for _, ev := range evs {
		if ev.Detected {
			e.term.Printf("meta", "DETECTED %s — %s", ev.RuleID, firstLine(ev.Summary))
		} else {
			all = false
			e.term.Printf("err", "MISS %s — no new alert yet", ev.RuleID)
		}
	}
	e.mu.Lock()
	if all {
		e.steps[idx].Status = statusDetected
	} else {
		e.steps[idx].Status = statusMissed
	}
	e.steps[idx].Evidence = evs
	e.steps[idx].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	st := e.steps[idx]
	e.mu.Unlock()
	return st, nil
}

func (e *demoEngine) esCounts(rules []string) map[string]int {
	out := make(map[string]int, len(rules))
	for _, r := range rules {
		raw, err := e.ssh.Run(fmt.Sprintf(
			`curl -sf -H 'Content-Type: application/json' 'http://127.0.0.1:9200/ghostcatcher-events/_count' -d '{"query":{"term":{"rule_id.keyword":"%s"}}}'`,
			r,
		))
		if err != nil {
			out[r] = 0
			continue
		}
		// {"count":N,...}
		n := 0
		if i := strings.Index(raw, `"count":`); i >= 0 {
			rest := raw[i+8:]
			rest = strings.TrimLeft(rest, " ")
			j := 0
			for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
				j++
			}
			n, _ = strconv.Atoi(rest[:j])
		}
		out[r] = n
	}
	return out
}

func (e *demoEngine) waitEvidence(rules []string, before map[string]int, secs int) []Evidence {
	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	evs := make([]Evidence, len(rules))
	for i, r := range rules {
		evs[i] = Evidence{RuleID: r, Title: humanRuleTitle(r), Summary: "Waiting for alert…"}
	}
	lastProgress := time.Time{}
	for time.Now().Before(deadline) {
		allFresh := true
		for i, r := range rules {
			raw, err := e.ssh.Run(fmt.Sprintf(
				`curl -sf -H 'Content-Type: application/json' 'http://127.0.0.1:9200/ghostcatcher-events/_search' -d '{"size":1,"sort":[{"timestamp":"desc"}],"query":{"term":{"rule_id.keyword":"%s"}}}'`,
				r,
			))
			if err != nil {
				allFresh = false
				continue
			}
			ev := parseESLatest(r, raw)
			counts := e.esCounts([]string{r})
			if counts[r] <= before[r] {
				ev.Detected = false
				ev.Summary = fmt.Sprintf("No new %s alert yet (count still %d).", r, counts[r])
				ev.Bullets = nil
				allFresh = false
				if time.Since(lastProgress) >= 5*time.Second {
					left := int(time.Until(deadline).Seconds())
					if left < 0 {
						left = 0
					}
					e.term.Printf("meta", "  … still waiting for new %s (before=%d now=%d, %ds left)",
						r, before[r], counts[r], left)
					lastProgress = time.Now()
				}
			}
			evs[i] = ev
			if !ev.Detected {
				allFresh = false
			}
		}
		if allFresh {
			return evs
		}
		time.Sleep(2 * time.Second)
	}
	return evs
}

func (e *demoEngine) health() map[string]any {
	cmd := `set -e
printf 'ghostcatcher=%s\n' "$(systemctl is-active ghostcatcher 2>/dev/null || echo down)"
printf 'elasticsearch=%s\n' "$(systemctl is-active elasticsearch 2>/dev/null || echo down)"
printf 'docker=%s\n' "$(systemctl is-active docker 2>/dev/null || echo down)"
if curl -sf --max-time 3 http://127.0.0.1:8888/ >/dev/null; then echo wp=up; else echo wp=down; fi
if curl -sf --max-time 3 http://127.0.0.1:9200 >/dev/null; then echo es_http=up; else echo es_http=down; fi
`
	e.term.Printf("meta", "")
	e.term.Printf("meta", "═══ host check ═══")
	e.term.Printf("cmd", "root@victim# %s", "systemctl is-active …; curl WP/ES")
	tw := &termWriter{hub: e.term, kind: "out"}
	out, err := e.ssh.RunStream(cmd, tw)
	tw.Flush()
	h := map[string]any{
		"target": e.target,
		"ssh":    err == nil,
		"raw":    strings.TrimSpace(out),
	}
	if err != nil {
		e.term.Printf("err", "health check failed: %v", err)
		h["error"] = err.Error()
	} else {
		e.term.Printf("meta", "host check done")
	}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			h[k] = v
		}
	}
	return h
}
