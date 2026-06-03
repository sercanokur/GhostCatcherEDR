// Package respond implements the OODA Act phase: audit-first active response.
package respond

import (
	"fmt"
	"os"
	"sync"
	"time"

	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/killchain"
	"ghostcatcher/internal/quarantine"
	"ghostcatcher/internal/rules"
)

const (
	ModeAudit   = "audit"
	ModeEnforce = "enforce"

	ActionAlertOnly      = "alert_only"
	ActionQuarantineFile = "quarantine_file"
	ActionKillProcess    = "kill_process"
	ActionIsolateHost    = "isolate_host"

	ResultAuditLogged = "audit_logged"
	ResultApplied     = "applied"
	ResultSkipped     = "skipped"
	ResultDenied      = "denied"
)

// Plan is the decided response for one event.
type Plan struct {
	Action string
	Mode   string
	Reason string
	Target string
}

// Engine executes OODA Act with safety rails.
type Engine struct {
	cfg    *config.ResponseConfig
	vault  *quarantine.Vault
	limits map[string][]time.Time
	mu     sync.Mutex
}

func NewEngine(cfg *config.ResponseConfig, vault *quarantine.Vault) *Engine {
	if cfg == nil {
		cfg = &config.ResponseConfig{}
	}
	return &Engine{cfg: cfg, vault: vault, limits: make(map[string][]time.Time)}
}

// Decide selects an action for e using global policy and optional rule hint.
func (eng *Engine) Decide(e *event.Event, rule rules.Rule) Plan {
	if eng.cfg == nil || !eng.cfg.Enabled || eng.cfg.KillSwitch {
		return Plan{Action: ActionAlertOnly, Mode: eng.mode(), Reason: "response_disabled", Target: ""}
	}
	if e.LearningOnly {
		return Plan{Action: ActionAlertOnly, Mode: eng.mode(), Reason: "learning_only", Target: ""}
	}
	if e.Confidence < eng.cfg.MinConfidence {
		return Plan{Action: ActionAlertOnly, Mode: eng.mode(), Reason: "below_min_confidence", Target: ""}
	}
	if !severityAtLeast(e.Severity, eng.cfg.MinSeverity) {
		return Plan{Action: ActionAlertOnly, Mode: eng.mode(), Reason: "below_min_severity", Target: ""}
	}

	action := ActionAlertOnly
	if rule.Response.Action != "" {
		action = rule.Response.Action
	} else {
		action = eng.defaultAction(e)
	}
	if !eng.actionEnabled(action) {
		return Plan{Action: ActionAlertOnly, Mode: eng.mode(), Reason: "action_disabled", Target: ""}
	}
	target := eng.targetFor(e, action)
	if eng.isProtected(e, target) {
		return Plan{Action: ActionAlertOnly, Mode: eng.mode(), Reason: "protected_target", Target: target}
	}
	if eng.cfg.RequireRoot && os.Geteuid() != 0 && action != ActionAlertOnly {
		return Plan{Action: ActionAlertOnly, Mode: eng.mode(), Reason: "require_root", Target: target}
	}
	if !eng.rateLimitOK(action) {
		return Plan{Action: ActionAlertOnly, Mode: eng.mode(), Reason: "rate_limited", Target: target}
	}
	return Plan{Action: action, Mode: eng.mode(), Reason: "policy_match", Target: target}
}

func (eng *Engine) defaultAction(e *event.Event) string {
	switch {
	case e.Entity.Type == event.EntityFile && e.Entity.Path != "":
		return ActionQuarantineFile
	case e.Entity.Type == event.EntityProcess && killchain.EarlyPhase(e.KillChainPhase):
		return ActionKillProcess
	case e.Severity == event.SeverityCritical:
		return ActionKillProcess
	default:
		return ActionAlertOnly
	}
}

func (eng *Engine) Apply(plan Plan, e *event.Event, observedAt time.Time) {
	latency := int64(0)
	if !observedAt.IsZero() {
		latency = time.Since(observedAt).Milliseconds()
	}
	rc := &event.ResponseContext{
		Action:        plan.Action,
		Mode:          plan.Mode,
		Reason:        plan.Reason,
		Target:        plan.Target,
		LoopLatencyMS: latency,
	}
	e.Response = rc

	if plan.Action == ActionAlertOnly {
		rc.Result = ResultSkipped
		return
	}

	if plan.Mode == ModeAudit {
		rc.Result = ResultAuditLogged
		return
	}

	var err error
	switch plan.Action {
	case ActionQuarantineFile:
		err = eng.quarantineFile(e, plan.Target)
	case ActionKillProcess:
		err = eng.killProcess(plan.Target)
	case ActionIsolateHost:
		err = eng.isolateHost()
	default:
		rc.Result = ResultSkipped
		return
	}
	if err != nil {
		rc.Result = ResultDenied
		rc.Reason = fmt.Sprintf("%s: %v", plan.Reason, err)
		return
	}
	rc.Result = ResultApplied
	eng.recordRate(plan.Action)
}

func (eng *Engine) quarantineFile(e *event.Event, path string) error {
	if eng.vault == nil || path == "" {
		return fmt.Errorf("quarantine vault unavailable")
	}
	_, err := eng.vault.Store(path, e)
	return err
}

func (eng *Engine) mode() string {
	if eng.cfg.Mode == ModeEnforce {
		return ModeEnforce
	}
	return ModeAudit
}

func (eng *Engine) actionEnabled(action string) bool {
	switch action {
	case ActionAlertOnly:
		return true
	case ActionQuarantineFile:
		return eng.cfg.AllowQuarantine
	case ActionKillProcess:
		return eng.cfg.AllowKillProcess
	case ActionIsolateHost:
		return eng.cfg.AllowIsolateHost
	default:
		return false
	}
}

func (eng *Engine) targetFor(e *event.Event, action string) string {
	switch action {
	case ActionQuarantineFile:
		if e.Entity.Path != "" {
			return e.Entity.Path
		}
		return e.Entity.ID
	case ActionKillProcess:
		if e.Process != nil && e.Process.PID > 0 {
			return fmt.Sprintf("pid:%d", e.Process.PID)
		}
		if e.Entity.Type == event.EntityProcess && e.Entity.ID != "" {
			return "pid:" + e.Entity.ID
		}
		return ""
	case ActionIsolateHost:
		return "host"
	default:
		return ""
	}
}

func (eng *Engine) isProtected(e *event.Event, target string) bool {
	if e.Process != nil {
		for _, p := range eng.cfg.ProtectedPIDs {
			if e.Process.PID == p {
				return true
			}
		}
		if commProtected(e.Process.Comm, eng.cfg.ProtectedComms) {
			return true
		}
	}
	for _, p := range eng.cfg.ProtectedPIDs {
		if target == fmt.Sprintf("pid:%d", p) {
			return true
		}
	}
	if e.Process != nil && commProtected(e.Process.Comm, eng.cfg.ProtectedComms) {
		return true
	}
	return false
}

func commProtected(comm string, list []string) bool {
	for _, p := range list {
		if p != "" && comm == p {
			return true
		}
	}
	return false
}

func (eng *Engine) rateLimitOK(action string) bool {
	if eng.cfg.RateLimitPerActionPerMin <= 0 || action == ActionAlertOnly {
		return true
	}
	eng.mu.Lock()
	defer eng.mu.Unlock()
	now := time.Now()
	cut := now.Add(-time.Minute)
	var kept []time.Time
	for _, t := range eng.limits[action] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	eng.limits[action] = kept
	return len(kept) < eng.cfg.RateLimitPerActionPerMin
}

func (eng *Engine) recordRate(action string) {
	if eng.cfg.RateLimitPerActionPerMin <= 0 {
		return
	}
	eng.mu.Lock()
	defer eng.mu.Unlock()
	eng.limits[action] = append(eng.limits[action], time.Now())
}

func severityAtLeast(sev event.Severity, min string) bool {
	if min == "" {
		return true
	}
	order := map[event.Severity]int{
		event.SeverityInfo: 0, event.SeverityLow: 1, event.SeverityMedium: 2,
		event.SeverityHigh: 3, event.SeverityCritical: 4,
	}
	want := map[string]int{
		"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
	}
	return order[sev] >= want[min]
}
