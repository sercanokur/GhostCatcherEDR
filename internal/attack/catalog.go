// Package attack provides MITRE ATT&CK coverage analysis for rule packs.
package attack

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"ghostcatcher/internal/rules"
)

// TechniqueMeta holds display metadata for a technique ID.
type TechniqueMeta struct {
	ID     string
	Tactic string
	Name   string
}

// BaselineTechniques is a curated set of high-value Linux endpoint techniques
// used for gap analysis when rules do not cover them.
var BaselineTechniques = []TechniqueMeta{
	{ID: "T1059.004", Tactic: "execution", Name: "Unix Shell"},
	{ID: "T1053.003", Tactic: "persistence", Name: "Cron"},
	{ID: "T1098.004", Tactic: "persistence", Name: "SSH Authorized Keys"},
	{ID: "T1574.006", Tactic: "defense-evasion", Name: "LD_PRELOAD"},
	{ID: "T1014", Tactic: "defense-evasion", Name: "Rootkit"},
	{ID: "T1055", Tactic: "defense-evasion", Name: "Process Injection"},
	{ID: "T1055.001", Tactic: "defense-evasion", Name: "Dynamic-link Library Injection"},
	{ID: "T1068", Tactic: "privilege-escalation", Name: "Exploitation for Privilege Escalation"},
	{ID: "T1036", Tactic: "defense-evasion", Name: "Masquerading"},
	{ID: "T1505.003", Tactic: "persistence", Name: "Web Shell"},
	{ID: "T1071.001", Tactic: "command-and-control", Name: "Web Protocols"},
	{ID: "T1048", Tactic: "exfiltration", Name: "Exfiltration Over Alternative Protocol"},
	{ID: "T1003", Tactic: "credential-access", Name: "OS Credential Dumping"},
	{ID: "T1021.004", Tactic: "lateral-movement", Name: "SSH"},
	{ID: "T1547.006", Tactic: "persistence", Name: "Kernel Modules and Extensions"},
	{ID: "T1562.001", Tactic: "defense-evasion", Name: "Disable or Modify Tools"},
}

// Coverage holds techniques covered by a rule pack vs the baseline set.
type Coverage struct {
	ByTactic   map[string][]string
	Covered    map[string]struct{}
	Uncovered  []string
	RuleCount  int
	TechCount  int
}

// Analyze builds coverage from a loaded rule pack.
func Analyze(pack *rules.Pack) Coverage {
	cov := Coverage{
		ByTactic:  make(map[string][]string),
		Covered:   make(map[string]struct{}),
		RuleCount: len(pack.Rules),
	}
	seenTech := map[string]struct{}{}
	for _, r := range pack.Rules {
		tac := r.Tactic
		if tac == "" {
			tac = "unknown"
		}
		for _, tid := range r.Techniques {
			if tid == "" {
				continue
			}
			cov.Covered[tid] = struct{}{}
			if _, ok := seenTech[tid]; !ok {
				seenTech[tid] = struct{}{}
				cov.ByTactic[tac] = append(cov.ByTactic[tac], tid)
			}
		}
	}
	cov.TechCount = len(cov.Covered)
	base := map[string]struct{}{}
	for _, m := range BaselineTechniques {
		base[m.ID] = struct{}{}
	}
	for id := range base {
		if _, ok := cov.Covered[id]; !ok {
			cov.Uncovered = append(cov.Uncovered, id)
		}
	}
	sort.Strings(cov.Uncovered)
	for tac := range cov.ByTactic {
		sort.Strings(cov.ByTactic[tac])
	}
	return cov
}

// SummaryText returns a human-readable coverage report.
func SummaryText(pack *rules.Pack) string {
	cov := Analyze(pack)
	var b strings.Builder
	fmt.Fprintf(&b, "Rule pack %s: %d rules, %d unique techniques\n", pack.Version, cov.RuleCount, cov.TechCount)
	tactics := make([]string, 0, len(cov.ByTactic))
	for t := range cov.ByTactic {
		tactics = append(tactics, t)
	}
	sort.Strings(tactics)
	for _, tac := range tactics {
		fmt.Fprintf(&b, "  %s: %s\n", tac, strings.Join(cov.ByTactic[tac], ", "))
	}
	if len(cov.Uncovered) > 0 {
		fmt.Fprintf(&b, "Gaps vs baseline (%d): %s\n", len(cov.Uncovered), strings.Join(cov.Uncovered, ", "))
	} else {
		b.WriteString("Gaps vs baseline: none\n")
	}
	return b.String()
}

// NavigatorLayer is ATT&CK Navigator layer JSON (subset).
type NavigatorLayer struct {
	Name        string                 `json:"name"`
	Versions    map[string]string      `json:"versions"`
	Techniques  []NavigatorTechnique   `json:"techniques"`
	Gradient    map[string]interface{} `json:"gradient"`
}

type NavigatorTechnique struct {
	TechniqueID string `json:"techniqueID"`
	Score       int    `json:"score"`
	Comment     string `json:"comment,omitempty"`
}

// BuildNavigatorLayer emits a Navigator-compatible layer for covered techniques.
func BuildNavigatorLayer(pack *rules.Pack) NavigatorLayer {
	cov := Analyze(pack)
	techs := make([]NavigatorTechnique, 0, len(cov.Covered))
	for id := range cov.Covered {
		techs = append(techs, NavigatorTechnique{TechniqueID: id, Score: 1, Comment: "ghostcatcher rule pack"})
	}
	sort.Slice(techs, func(i, j int) bool { return techs[i].TechniqueID < techs[j].TechniqueID })
	return NavigatorLayer{
		Name: "GhostCatcher " + pack.Version,
		Versions: map[string]string{
			"attack": "15",
			"navigator": "5",
			"layer": "4.5",
		},
		Techniques: techs,
		Gradient: map[string]interface{}{
			"colors": []string{"#ff6666", "#ffe766", "#8ec843"},
			"minValue": 0,
			"maxValue": 1,
		},
	}
}

// WriteNavigatorLayer writes Navigator JSON to path.
func WriteNavigatorLayer(pack *rules.Pack, path string) error {
	layer := BuildNavigatorLayer(pack)
	b, err := json.MarshalIndent(layer, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
