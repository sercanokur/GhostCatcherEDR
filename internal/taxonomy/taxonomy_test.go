package taxonomy

import (
	"path/filepath"
	"runtime"
	"testing"

	"ghostcatcher/internal/event"
)

func TestLoadMapping(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	m, err := Load(filepath.Join(root, "configs", "mapping.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Nanos) < 80 {
		t.Fatalf("expected full catalog, got %d", len(m.Nanos))
	}
	if err := m.MustHave("WEB_SHELL_PATTERN", "NETWORK_IMDS_ACCESS", "CHAIN-1"); err == nil {
		// CHAIN-1 is not a nano
	}
	if err := m.MustHave("WEB_SHELL_PATTERN", "NETWORK_IMDS_ACCESS", "CONTAINER_SOCKET_ACCESS"); err != nil {
		t.Fatal(err)
	}
	if len(m.Chains) != 6 {
		t.Fatalf("chains=%d", len(m.Chains))
	}
	SetGlobal(m)
	ev := &event.Event{RuleID: "WEB_SHELL_PATTERN"}
	Apply(ev)
	if ev.Macro != "M1" || ev.Micro != "M1.1" || ev.Src != "FIM" {
		t.Fatalf("apply failed: %+v", ev)
	}
}
