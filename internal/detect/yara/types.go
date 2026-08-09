package yara

import "errors"

// Match is one libyara rule match. On disk scans Path is the file; on
// memory scans Pid + Region locate the hit. Defined without build tags so
// both the stub (!with_yara) and cgo (with_yara) builds share the type —
// golangci-lint enables with_yara via .golangci.yml.
type Match struct {
	RuleID  string
	Tags    []string
	Path    string
	Pid     int
	Region  string
	Offset  uint64
	Excerpt string
}

// ErrDisabled is returned when the caller tries to use a YARA-only API
// without enabling the build tag.
var ErrDisabled = errors.New("yara: built without with_yara tag")
