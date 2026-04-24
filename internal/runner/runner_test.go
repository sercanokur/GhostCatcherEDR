package runner

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/detect/web"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/rules"
)

func TestRunOnce_WebShellLearningWithoutBaseline(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.BaselinePath = filepath.Join(dir, "baseline.json")
	cfg.RulePackPath = filepath.Join("..", "..", "configs", "rule_pack.example.yaml")
	if _, err := os.Stat(cfg.RulePackPath); err != nil {
		cfg.RulePackPath = "configs/rule_pack.example.yaml"
	}
	cfg.DocumentRoots = []string{filepath.Join("..", "..", "testdata", "webroot")}
	if _, err := os.Stat(cfg.DocumentRoots[0]); err != nil {
		cfg.DocumentRoots = []string{"testdata/webroot"}
	}
	cfg.ScanInterval = config.Duration(time.Second)
	cfg.MinConfidenceAlert = 70
	cfg.LearningMode = false

	pack, err := rules.LoadPack(cfg.RulePackPath)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	r := New(cfg, pack).WithOutput(&buf)
	if err := r.RunOnce(); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	var found bool
	for {
		var ev event.Event
		if err := dec.Decode(&ev); err != nil {
			break
		}
		if ev.RuleID == "WEB_SHELL_PATTERN" {
			found = true
			if ev.SchemaVersion != event.SchemaVersion {
				t.Fatal()
			}
			break
		}
	}
	if !found {
		t.Fatal("expected WEB_SHELL_PATTERN in output")
	}
}

func TestRunOnce_NoAlertWhenBaselineMatches(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.BaselinePath = filepath.Join(dir, "baseline.json")
	cfg.RulePackPath = "configs/rule_pack.example.yaml"
	cfg.DocumentRoots = []string{"testdata/webroot"}
	if _, err := os.Stat(cfg.DocumentRoots[0]); err != nil {
		t.Skip("testdata/webroot missing")
	}
	pack, err := rules.LoadPack(cfg.RulePackPath)
	if err != nil {
		t.Fatal(err)
	}
	snap := baseline.EmptySnapshot()
	_ = web.BuildBaselineWebFiles(cfg, snap)
	snap.CommittedAt = time.Now().UTC()
	_ = snap.Save(cfg.BaselinePath)

	var buf bytes.Buffer
	r := New(cfg, pack).WithOutput(&buf)
	if err := r.RunOnce(); err != nil {
		t.Fatal(err)
	}
	// May still emit LD_PRELOAD/SSH noise on dev machine; filter web rule
	dec := json.NewDecoder(&buf)
	for {
		var ev event.Event
		if err := dec.Decode(&ev); err != nil {
			break
		}
		if ev.RuleID == "WEB_SHELL_PATTERN" && !ev.LearningOnly {
			t.Fatalf("expected learning or no web event after baseline, got %+v", ev)
		}
	}
}
