package attack

import (
	"testing"

	"ghostcatcher/internal/rules"
)

func TestAnalyze_Gaps(t *testing.T) {
	pack := &rules.Pack{
		Version: "test",
		Rules: []rules.Rule{
			{ID: "A", Techniques: []string{"T1053.003"}, Tactic: "persistence"},
		},
	}
	cov := Analyze(pack)
	if _, ok := cov.Covered["T1053.003"]; !ok {
		t.Fatal("expected T1053.003 covered")
	}
	if len(cov.Uncovered) == 0 {
		t.Fatal("expected gaps")
	}
	found := false
	for _, id := range cov.Uncovered {
		if id == "T1003" {
			found = true
		}
	}
	if !found {
		t.Fatal("T1003 should be a gap")
	}
}

func TestBuildNavigatorLayer(t *testing.T) {
	pack := &rules.Pack{
		Version: "1.0",
		Rules: []rules.Rule{{ID: "X", Techniques: []string{"T1055"}, Tactic: "defense-evasion"}},
	}
	layer := BuildNavigatorLayer(pack)
	if len(layer.Techniques) != 1 || layer.Techniques[0].TechniqueID != "T1055" {
		t.Fatalf("layer=%+v", layer.Techniques)
	}
}
