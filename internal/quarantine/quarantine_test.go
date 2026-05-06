package quarantine

import (
	"os"
	"path/filepath"
	"testing"

	"ghostcatcher/internal/event"
)

func TestStore_WritesFileAndSidecar(t *testing.T) {
	dir := t.TempDir()
	v, err := New(filepath.Join(dir, "vault"))
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "ws.php")
	if err := os.WriteFile(src, []byte("<?php eval($_GET[x]); ?>"), 0o644); err != nil {
		t.Fatal(err)
	}
	ev := &event.Event{RuleID: "WEB_SHELL_PATTERN", Confidence: 95, Signals: []string{"s1"}}
	dst, err := v.Store(src, ev)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("bin missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dst), filepath.Base(dst[:len(dst)-4])+".json")); err != nil {
		t.Fatalf("sidecar missing: %v", err)
	}
}
