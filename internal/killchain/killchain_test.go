package killchain

import "testing"

func TestPhaseFor(t *testing.T) {
	tests := []struct {
		tactic, override, want string
	}{
		{"execution", "", PhaseExploitation},
		{"persistence", "", PhaseInstallation},
		{"command-and-control", "", PhaseCommandAndControl},
		{"credential-access", "", PhaseActionsOnObjectives},
		{"execution", "installation", PhaseInstallation},
		{"", "c2", PhaseCommandAndControl},
	}
	for _, tc := range tests {
		got := PhaseFor(tc.tactic, tc.override)
		if got != tc.want {
			t.Errorf("PhaseFor(%q,%q)=%q want %q", tc.tactic, tc.override, got, tc.want)
		}
	}
}

func TestEarlyPhase(t *testing.T) {
	if !EarlyPhase(PhaseExploitation) || !EarlyPhase(PhaseInstallation) {
		t.Fatal("expected early phases")
	}
	if EarlyPhase(PhaseCommandAndControl) {
		t.Fatal("c2 should not be early")
	}
}
