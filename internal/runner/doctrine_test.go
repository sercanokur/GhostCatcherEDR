package runner

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"ghostcatcher/internal/config"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/killchain"
	"ghostcatcher/internal/respond"
	"ghostcatcher/internal/rules"
)

func TestProcessEvent_OODAFields(t *testing.T) {
	cfg := config.Default()
	cfg.Respond.Enabled = true
	cfg.Respond.Mode = respond.ModeAudit
	cfg.MinConfidenceAlert = 50
	pack := &rules.Pack{
		Version: "test",
		Rules: []rules.Rule{{
			ID:             "CREDENTIAL_ACCESS_PROC_DUMP",
			Techniques:     []string{"T1003"},
			Tactic:         "credential-access",
			KillChainPhase: killchain.PhaseActionsOnObjectives,
			MinSignals:     1,
			BaseScore:      92,
			CapScore:       100,
			Response:       rules.RuleResponse{Action: respond.ActionKillProcess},
		}},
	}
	var buf bytes.Buffer
	r := New(cfg, pack).WithOutput(&buf)
	observed := time.Now().Add(-12 * time.Millisecond)
	e := &event.Event{
		SchemaVersion: event.SchemaVersion,
		RuleID:        "CREDENTIAL_ACCESS_PROC_DUMP",
		Tactic:        "credential-access",
		TechniqueIDs:  []string{"T1003"},
		Confidence:    92,
		Severity:      event.SeverityCritical,
		Entity:        event.Entity{Type: event.EntityProcess, ID: "4242"},
		Process:       &event.ProcessContext{PID: 4242, Comm: "mimikatz-analog"},
	}
	r.processEvent(e, observed, time.Now().UTC())
	if e.KillChainPhase != killchain.PhaseActionsOnObjectives {
		t.Fatalf("phase=%s", e.KillChainPhase)
	}
	if e.Response == nil || e.Response.Mode != respond.ModeAudit {
		t.Fatalf("response=%+v", e.Response)
	}
	if e.Response.LoopLatencyMS < 5 {
		t.Fatalf("latency=%d", e.Response.LoopLatencyMS)
	}
	dec := json.NewDecoder(&buf)
	var out event.Event
	if err := dec.Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out.SOCEscalate || out.DefenseLayer != event.DefenseLayerEndpoint {
		t.Fatalf("soc=%v layer=%s", out.SOCEscalate, out.DefenseLayer)
	}
}
