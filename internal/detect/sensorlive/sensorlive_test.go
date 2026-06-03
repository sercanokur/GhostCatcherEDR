package sensorlive

import (
	"testing"
	"time"

	"ghostcatcher/internal/config"
	"ghostcatcher/internal/rules"
	"ghostcatcher/internal/sensor"
)

func testPack() *rules.Pack {
	return &rules.Pack{
		Version: "test",
		Rules: []rules.Rule{
			{ID: RulePtrace, Techniques: []string{"T1055"}, Tactic: "defense-evasion", MinSignals: 1, BaseScore: 85, CapScore: 100},
			{ID: RuleMemfdCreate, Techniques: []string{"T1055.001"}, Tactic: "execution", MinSignals: 1, BaseScore: 82, CapScore: 100},
		},
	}
}

func TestRouteSensorEvent_Ptrace(t *testing.T) {
	cfg := config.Default()
	when := time.Now().Add(-20 * time.Millisecond)
	ev := sensor.Event{Kind: sensor.KindPtrace, PID: 99, Comm: "evil", When: when}
	out, hit := RouteSensorEvent(cfg, testPack(), "test", ev)
	if !hit || out.RuleID != RulePtrace {
		t.Fatalf("hit=%v rule=%s", hit, out.RuleID)
	}
}
