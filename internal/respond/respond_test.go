package respond

import (
	"testing"
	"time"

	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/killchain"
	"ghostcatcher/internal/rules"
)

func TestDecide_AuditDefault(t *testing.T) {
	cfg := config.Default().Respond
	cfg.Enabled = true
	cfg.RequireRoot = false
	eng := NewEngine(&cfg, nil)
	e := &event.Event{
		Confidence:     90,
		Severity:       event.SeverityHigh,
		KillChainPhase: killchain.PhaseExploitation,
		Entity:         event.Entity{Type: event.EntityProcess, ID: "42"},
		Process:        &event.ProcessContext{PID: 42, Comm: "evil"},
	}
	plan := eng.Decide(e, rules.Rule{Response: rules.RuleResponse{Action: ActionKillProcess}})
	if plan.Action != ActionKillProcess || plan.Mode != ModeAudit {
		t.Fatalf("plan=%+v", plan)
	}
	eng.Apply(plan, e, time.Now().Add(-50*time.Millisecond))
	if e.Response.Result != ResultAuditLogged {
		t.Fatalf("result=%s want audit_logged", e.Response.Result)
	}
	if e.Response.LoopLatencyMS < 40 {
		t.Fatalf("latency=%d want ~50ms", e.Response.LoopLatencyMS)
	}
}

func TestDecide_ProtectedPID(t *testing.T) {
	cfg := config.Default().Respond
	cfg.Enabled = true
	cfg.ProtectedPIDs = []int{1}
	eng := NewEngine(&cfg, nil)
	e := &event.Event{
		Confidence: 99,
		Severity:   event.SeverityCritical,
		Entity:     event.Entity{Type: event.EntityProcess, ID: "1"},
		Process:    &event.ProcessContext{PID: 1, Comm: "systemd"},
	}
	plan := eng.Decide(e, rules.Rule{Response: rules.RuleResponse{Action: ActionKillProcess}})
	if plan.Reason != "protected_target" {
		t.Fatalf("reason=%s", plan.Reason)
	}
}

func TestDecide_KillSwitch(t *testing.T) {
	cfg := config.Default().Respond
	cfg.Enabled = true
	cfg.KillSwitch = true
	eng := NewEngine(&cfg, nil)
	e := &event.Event{Confidence: 100, Severity: event.SeverityCritical}
	plan := eng.Decide(e, rules.Rule{})
	if plan.Reason != "response_disabled" {
		t.Fatal(plan.Reason)
	}
}
