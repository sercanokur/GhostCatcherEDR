package runner

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"ghostcatcher/internal/config"
	"ghostcatcher/internal/rules"
)

func benchRunner(b *testing.B) *Runner {
	b.Helper()
	dir := b.TempDir()
	cfg := config.Default()
	cfg.BaselinePath = filepath.Join(dir, "baseline.json")
	cfg.RulePackPath = findRulePack(b)
	cfg.DocumentRoots = []string{findWebroot(b)}
	cfg.NetworkScanEnabled = false
	cfg.AncestryScanEnabled = false
	cfg.IntegrityVerifyEnabled = false
	cfg.CopyFail.Enabled = false
	cfg.SuddenRoot.Enabled = false
	cfg.WatchSensitivePaths = false
	pack, err := rules.LoadPack(cfg.RulePackPath)
	if err != nil {
		b.Fatal(err)
	}
	return New(cfg, pack).WithOutput(&bytes.Buffer{})
}

func findRulePack(t testing.TB) string {
	t.Helper()
	for _, p := range []string{
		"configs/rule_pack.example.yaml",
		filepath.Join("..", "..", "configs", "rule_pack.example.yaml"),
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("rule pack not found")
	return ""
}

func findWebroot(t testing.TB) string {
	t.Helper()
	for _, p := range []string{
		"testdata/webroot",
		filepath.Join("..", "..", "testdata", "webroot"),
	} {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return p
		}
	}
	t.Skip("testdata/webroot missing")
	return ""
}

func BenchmarkRunOnce(b *testing.B) {
	r := benchRunner(b)
	b.ReportAllocs()
	for b.Loop() {
		if err := r.RunOnce(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRunFIMOnce(b *testing.B) {
	r := benchRunner(b)
	b.ReportAllocs()
	for b.Loop() {
		if err := r.RunFIMOnce(); err != nil {
			b.Fatal(err)
		}
	}
}
