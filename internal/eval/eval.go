// Package eval drives a precision/recall/F1 evaluation of the detection
// stack against a labeled corpus. The corpus layout is:
//
//	<root>/malicious/...   - each file/line is a true positive
//	<root>/benign/...      - each file/line is a true negative
//	<root>/cron/malicious.txt, <root>/cron/benign.txt
//
// The eval command wires every file through the web and cron detectors
// and computes aggregate metrics. It is intentionally deterministic so
// CI can gate on a regression threshold.
package eval

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/detect/persistence"
	"ghostcatcher/internal/detect/web"
	"ghostcatcher/internal/rules"
)

// Result captures one evaluation run.
type Result struct {
	TruePositives  int
	FalsePositives int
	TrueNegatives  int
	FalseNegatives int
}

// Precision = TP / (TP + FP).
func (r Result) Precision() float64 {
	if r.TruePositives+r.FalsePositives == 0 {
		return 0
	}
	return float64(r.TruePositives) / float64(r.TruePositives+r.FalsePositives)
}

// Recall = TP / (TP + FN).
func (r Result) Recall() float64 {
	if r.TruePositives+r.FalseNegatives == 0 {
		return 0
	}
	return float64(r.TruePositives) / float64(r.TruePositives+r.FalseNegatives)
}

// F1 harmonic mean.
func (r Result) F1() float64 {
	p, rec := r.Precision(), r.Recall()
	if p+rec == 0 {
		return 0
	}
	return 2 * p * rec / (p + rec)
}

// Run walks root and scores the detectors. Pack may be nil to use the
// default thresholds hard-coded into the detectors.
func Run(root string, cfg *config.Config, pack *rules.Pack) (Result, error) {
	if pack == nil {
		pack = &rules.Pack{Version: "eval", Rules: nil}
	}
	snap := baseline.EmptySnapshot()
	var res Result
	// --- web corpus ---
	webCfg := *cfg
	webCfg.LearningMode = false
	webCfg.FirstRunAllowAlerts = true
	webCfg.MinConfidenceAlert = 60

	for _, label := range []string{"malicious", "benign"} {
		subdir := filepath.Join(root, label)
		if _, err := os.Stat(subdir); err != nil {
			continue
		}
		webCfg.DocumentRoots = []string{subdir}
		webCfg.PathAllowlist = nil
		events, err := web.Scan(&webCfg, snap, pack, "eval")
		if err != nil {
			continue
		}
		hits := map[string]bool{}
		for _, e := range events {
			// Any signal (even learning-only) counts as a detection.
			// Consumers of the corpus care whether the engine flags it
			// at all; severity tuning is a separate axis.
			hits[e.Entity.Path] = true
		}
		_ = filepath.WalkDir(subdir, func(p string, d fs.DirEntry, _ error) error {
			if d == nil || d.IsDir() {
				return nil
			}
			hit := hits[p]
			switch label {
			case "malicious":
				if hit {
					res.TruePositives++
				} else {
					res.FalseNegatives++
				}
			case "benign":
				if hit {
					res.FalsePositives++
				} else {
					res.TrueNegatives++
				}
			}
			return nil
		})
	}

	// --- cron corpus (line-oriented) ---
	cronDir := filepath.Join(root, "cron")
	if _, err := os.Stat(cronDir); err == nil {
		res = runCronLines(cronDir, res)
	}
	return res, nil
}

func runCronLines(dir string, res Result) Result {
	for _, label := range []string{"malicious", "benign"} {
		f, err := os.Open(filepath.Join(dir, label+".txt"))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			hit := persistence.EvalCronLine(line)
			switch label {
			case "malicious":
				if hit {
					res.TruePositives++
				} else {
					res.FalseNegatives++
				}
			case "benign":
				if hit {
					res.FalsePositives++
				} else {
					res.TrueNegatives++
				}
			}
		}
		f.Close()
	}
	return res
}

// Report formats a result as a human-readable block.
func (r Result) Report() string {
	return fmt.Sprintf(
		"tp=%d fp=%d fn=%d tn=%d | precision=%.3f recall=%.3f f1=%.3f",
		r.TruePositives, r.FalsePositives, r.FalseNegatives, r.TrueNegatives,
		r.Precision(), r.Recall(), r.F1(),
	)
}
