package web

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/rules"
)

func BenchmarkWebScan_Tiny(b *testing.B) {
	root := findWebroot(b)
	cfg, pack := benchWebCfg(b, root)
	snap := baseline.EmptySnapshot()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Scan(cfg, snap, pack, "bench"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWebScan_Busy(b *testing.B) {
	dir := b.TempDir()
	const n = 500
	for i := 0; i < n; i++ {
		name := filepath.Join(dir, fmt.Sprintf("f%04d.php", i))
		body := []byte("<?php echo 'ok';\n")
		if i%50 == 0 {
			body = []byte("<?php eval($_POST['x']);\n")
		}
		if err := os.WriteFile(name, body, 0o644); err != nil {
			b.Fatal(err)
		}
	}
	cfg, pack := benchWebCfg(b, dir)
	snap := baseline.EmptySnapshot()
	// Commit baseline so mtime+size gate engages after first pass.
	if err := BuildBaselineWebFiles(cfg, snap); err != nil {
		b.Fatal(err)
	}
	snap.CommittedAt = time.Now().UTC()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Scan(cfg, snap, pack, "bench"); err != nil {
			b.Fatal(err)
		}
	}
}

func benchWebCfg(b *testing.B, root string) (*config.Config, *rules.Pack) {
	b.Helper()
	cfg := config.Default()
	cfg.DocumentRoots = []string{root}
	cfg.PathAllowlist = nil
	cfg.FirstRunAllowAlerts = true
	packPath := findRulePack(b)
	pack, err := rules.LoadPack(packPath)
	if err != nil {
		b.Fatal(err)
	}
	return cfg, pack
}

func findWebroot(t testing.TB) string {
	t.Helper()
	for _, p := range []string{
		filepath.Join("..", "..", "..", "testdata", "webroot"),
		"testdata/webroot",
	} {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return p
		}
	}
	t.Skip("testdata/webroot missing")
	return ""
}

func findRulePack(t testing.TB) string {
	t.Helper()
	for _, p := range []string{
		filepath.Join("..", "..", "..", "configs", "rule_pack.example.yaml"),
		"configs/rule_pack.example.yaml",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("rule pack missing")
	return ""
}
