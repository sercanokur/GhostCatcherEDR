package privesc

import (
	"os"
	"testing"

	"ghostcatcher/internal/config"
	"ghostcatcher/internal/rules"
)

func BenchmarkSuddenRootSnapshot(b *testing.B) {
	if _, err := os.Stat("/proc"); err != nil {
		b.Skip("/proc unavailable")
	}
	cfg := config.Default()
	cfg.SuddenRoot.Enabled = true
	pack := &rules.Pack{Version: "bench"}
	tracker := NewTracker(8192)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Snapshot(cfg, pack, "bench", tracker); err != nil {
			b.Fatal(err)
		}
	}
}
