package runner

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ghostcatcher/internal/config"
	"ghostcatcher/internal/rules"
)

// TestHostScanBudget_RunOnce fails if a full scan over the tiny
// testdata/webroot fixture exceeds a CI-friendly wall-time ceiling.
// This catches accidental O(n²) regressions without flaky benchstat.
func TestHostScanBudget_RunOnce(t *testing.T) {
	const maxWall = 5 * time.Second
	dir := t.TempDir()
	cfg := config.Default()
	cfg.BaselinePath = filepath.Join(dir, "baseline.json")
	cfg.RulePackPath = findRulePack(t)
	cfg.DocumentRoots = []string{findWebroot(t)}
	cfg.NetworkScanEnabled = false
	cfg.AncestryScanEnabled = false
	cfg.IntegrityVerifyEnabled = false
	cfg.CopyFail.Enabled = false
	cfg.SuddenRoot.Enabled = false
	pack, err := rules.LoadPack(cfg.RulePackPath)
	if err != nil {
		t.Fatal(err)
	}
	r := New(cfg, pack).WithOutput(&bytes.Buffer{})
	start := time.Now()
	if err := r.RunOnce(); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if elapsed > maxWall {
		t.Fatalf("RunOnce took %v (budget %v); see configs/profiles and scan.budget logs", elapsed, maxWall)
	}
	t.Logf("RunOnce wall=%v overlapping_skipped=%d", elapsed, r.OverlappingSkipped())
}

func TestConfigProfiles_Validate(t *testing.T) {
	root := moduleRoot(t)
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(old) }()

	ents, err := os.ReadDir(filepath.Join("configs", "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		path := filepath.Join("configs", "profiles", e.Name())
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatalf("%s: load: %v", e.Name(), err)
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("%s: validate: %v", e.Name(), err)
		}
		if _, err := rules.LoadPack(cfg.RulePackPath); err != nil {
			t.Fatalf("%s: rule pack %q: %v", e.Name(), cfg.RulePackPath, err)
		}
	}
}

func moduleRoot(t testing.TB) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
