//go:build !with_yara

// Package yara provides disk and process memory scanning via libyara. When
// the agent is built without the `with_yara` tag (the default in this
// repo to avoid a hard cgo dependency) this stub satisfies the API surface
// and always returns "no matches".
package yara

import "errors"

// Match is one libyara rule match. On disk scans Path is the file; on
// memory scans Pid + Region locate the hit.
type Match struct {
	RuleID  string
	Tags    []string
	Path    string
	Pid     int
	Region  string
	Offset  uint64
	Excerpt string
}

// Scanner is a compiled rule set ready to match. The stub implementation
// is intentionally no-op: Close/ScanFile/ScanProcess never return matches
// and never error, so callers can always keep the code path active.
type Scanner struct{}

// ErrDisabled is returned when the caller tries to use a YARA-only API
// without enabling the build tag.
var ErrDisabled = errors.New("yara: built without with_yara tag")

// New compiles every *.yar / *.yara file under dir. In the stub, this
// always returns ErrDisabled so operators who ship without YARA know.
func New(dir string) (*Scanner, error) {
	return nil, ErrDisabled
}

// Close releases any libyara state. No-op in the stub.
func (s *Scanner) Close() {}

// ScanFile scans path on disk. Stub always returns no matches.
func (s *Scanner) ScanFile(path string) ([]Match, error) { return nil, nil }

// ScanProcess scans live memory of pid. Stub always returns no matches.
func (s *Scanner) ScanProcess(pid int) ([]Match, error) { return nil, nil }

// Enabled reports whether libyara is compiled in. Used to skip initialization
// logging on stub builds.
func Enabled() bool { return false }
