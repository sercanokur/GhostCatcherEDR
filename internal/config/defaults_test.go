package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefault_HostPerfPhase1(t *testing.T) {
	c := Default()
	if c.SuddenRoot.SnapshotInterval.Duration() != 10*time.Second {
		t.Fatalf("sudden_root.snapshot_interval=%v want 10s", c.SuddenRoot.SnapshotInterval.Duration())
	}
	if c.CopyFail.PageCacheCheckEnabled {
		t.Fatal("copy_fail.page_cache_check_enabled should default false")
	}
	if !c.CopyFail.Enabled {
		t.Fatal("copy_fail.enabled should stay true (live leg)")
	}
}

func TestDefault_HostPerfPhase2(t *testing.T) {
	c := Default()
	if c.NetworkScanInterval.Duration() != 15*time.Minute {
		t.Fatalf("network_scan_interval=%v want 15m", c.NetworkScanInterval.Duration())
	}
	if c.IntegrityScanInterval.Duration() != 6*time.Hour {
		t.Fatalf("integrity_scan_interval=%v want 6h", c.IntegrityScanInterval.Duration())
	}
}

func TestLoad_ZeroSuddenRootIntervalUsesDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfg.yaml")
	body := []byte(`
baseline_path: ./b.json
rule_pack_path: ./r.yaml
sudden_root:
  enabled: true
  snapshot_interval: 0s
`)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.SuddenRoot.SnapshotInterval.Duration() != 10*time.Second {
		t.Fatalf("got %v want 10s", c.SuddenRoot.SnapshotInterval.Duration())
	}
}
