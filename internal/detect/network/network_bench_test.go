package network

import (
	"testing"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/rules"
)

func BenchmarkNetworkScan(b *testing.B) {
	cfg := config.Default()
	cfg.NetworkScanEnabled = true
	pack := &rules.Pack{Version: "bench"}
	snap := baseline.EmptySnapshot()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Scan(cfg, snap, pack, "bench"); err != nil {
			b.Fatal(err)
		}
	}
}
