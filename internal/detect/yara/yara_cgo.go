//go:build with_yara

package yara

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	yr "github.com/hillu/go-yara/v4"
)

// Scanner is a compiled ruleset + runtime configuration.
type Scanner struct {
	rules *yr.Rules
}

// Enabled reports whether libyara is compiled in.
func Enabled() bool { return true }

// New compiles every *.yar / *.yara file under dir. Returns an error if
// no rules compile; partial errors are surfaced.
func New(dir string) (*Scanner, error) {
	comp, err := yr.NewCompiler()
	if err != nil {
		return nil, err
	}
	var added int
	err = filepath.WalkDir(dir, func(p string, d os.DirEntry, werr error) error {
		if werr != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		if !(strings.HasSuffix(name, ".yar") || strings.HasSuffix(name, ".yara")) {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		defer f.Close()
		if err := comp.AddFile(f, filepath.Base(p)); err != nil {
			return nil
		}
		added++
		return nil
	})
	if err != nil {
		return nil, err
	}
	if added == 0 {
		return nil, fmt.Errorf("yara: no rule files under %s", dir)
	}
	rules, err := comp.GetRules()
	if err != nil {
		return nil, err
	}
	return &Scanner{rules: rules}, nil
}

// Close frees compiled rules.
func (s *Scanner) Close() {
	if s == nil || s.rules == nil {
		return
	}
	s.rules.Destroy()
	s.rules = nil
}

// ScanFile scans a file on disk.
func (s *Scanner) ScanFile(path string) ([]Match, error) {
	if s == nil || s.rules == nil {
		return nil, nil
	}
	var ms yr.MatchRules
	if err := s.rules.ScanFile(path, 0, 0, &ms); err != nil {
		return nil, err
	}
	return toMatchesFile(path, ms), nil
}

// ScanProcess scans the live memory of pid.
func (s *Scanner) ScanProcess(pid int) ([]Match, error) {
	if s == nil || s.rules == nil {
		return nil, nil
	}
	var ms yr.MatchRules
	if err := s.rules.ScanProc(pid, 0, 0, &ms); err != nil {
		return nil, err
	}
	out := make([]Match, 0, len(ms))
	for _, m := range ms {
		out = append(out, Match{
			RuleID: m.Rule,
			Tags:   m.Tags,
			Pid:    pid,
		})
	}
	return out, nil
}

func toMatchesFile(path string, ms yr.MatchRules) []Match {
	out := make([]Match, 0, len(ms))
	for _, m := range ms {
		out = append(out, Match{
			RuleID: m.Rule,
			Tags:   m.Tags,
			Path:   path,
		})
	}
	return out
}
