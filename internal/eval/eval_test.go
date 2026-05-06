package eval

import (
	"path/filepath"
	"testing"

	"ghostcatcher/internal/config"
)

func TestCorpusAboveThreshold(t *testing.T) {
	cfg := config.Default()
	cfg.LearningMode = false
	cfg.FirstRunAllowAlerts = true
	root := filepath.Join("..", "..", "testdata", "eval")
	res, err := Run(root, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.F1() < 0.85 {
		t.Fatalf("F1 regressed: %s", res.Report())
	}
	if res.Precision() < 0.95 {
		t.Fatalf("precision regressed: %s", res.Report())
	}
}
