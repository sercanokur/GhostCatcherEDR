package rules

import (
	"testing"

	"ghostcatcher/internal/event"
)

func TestScore_MinSignals(t *testing.T) {
	p := &Pack{
		Version: "1",
		Rules: []Rule{
			{ID: "R1", MinSignals: 2, BaseScore: 50, PerSignal: 10, CapScore: 100},
		},
	}
	c, ok := Score(p, "R1", []string{"a"})
	if !ok || c != 50 {
		t.Fatalf("expected base 50, got %d ok=%v", c, ok)
	}
	c, ok = Score(p, "R1", []string{"a", "b"})
	if !ok || c != 60 {
		t.Fatalf("expected 60, got %d", c)
	}
}

func TestSeverityFromConfidence(t *testing.T) {
	if SeverityFromConfidence(96, false) != event.SeverityCritical {
		t.Fatal()
	}
	if SeverityFromConfidence(50, true) != event.SeverityInfo {
		t.Fatal()
	}
}
