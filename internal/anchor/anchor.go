// Package anchor resolves bhv.md primary context anchors from cgroup paths
// and systemd units. Process names are never the primary anchor.
package anchor

import (
	"path"
	"regexp"
	"strconv"
	"strings"

	"ghostcatcher/internal/procfs"
)

var (
	reSystemSlice = regexp.MustCompile(`(?:^|/)(system\.slice/[^/\s]+\.service)(?:/|$)`)
	reUserSlice   = regexp.MustCompile(`(?:^|/)(user\.slice/user-\d+\.slice/[^/\s]+\.service)(?:/|$)`)
	reAnyUnit     = regexp.MustCompile(`((?:system|user)\.slice/[^\s/]+(?:\.service|\.scope|\.socket))`)
)

// Info is the resolved primary anchor for a process.
type Info struct {
	Cgroup      string // raw /proc/pid/cgroup text (first useful line)
	CgroupPath  string // cgroup v2 path segment
	SystemdUnit string // e.g. nginx.service or system.slice/nginx.service
	Anchor      string // preferred correlation key (unit if known, else path)
}

// FromPID reads cgroup and derives systemd unit / primary anchor.
func FromPID(pid int) Info {
	raw, err := procfs.ReadCgroup(pid)
	if err != nil {
		return Info{}
	}
	return FromCgroup(raw)
}

// FromCgroup parses raw /proc/pid/cgroup contents.
func FromCgroup(raw string) Info {
	info := Info{Cgroup: strings.TrimSpace(raw)}
	line := firstCgroupPath(raw)
	info.CgroupPath = line
	if u := extractUnit(line); u != "" {
		info.SystemdUnit = u
		info.Anchor = u
		return info
	}
	info.Anchor = line
	return info
}

func firstCgroupPath(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// cgroup v2: "0::/system.slice/nginx.service"
		// cgroup v1: "12:name=systemd:/system.slice/nginx.service"
		if i := strings.LastIndex(line, ":"); i >= 0 {
			p := line[i+1:]
			if p != "" && p != "/" {
				return p
			}
		}
	}
	return ""
}

func extractUnit(cgroupPath string) string {
	if cgroupPath == "" {
		return ""
	}
	if m := reSystemSlice.FindStringSubmatch(cgroupPath); len(m) > 1 {
		return path.Base(m[1])
	}
	if m := reUserSlice.FindStringSubmatch(cgroupPath); len(m) > 1 {
		return path.Base(m[1])
	}
	if m := reAnyUnit.FindStringSubmatch(cgroupPath); len(m) > 1 {
		return path.Base(m[1])
	}
	// Fallback: last path element ending in .service/.scope/.socket
	base := path.Base(cgroupPath)
	switch {
	case strings.HasSuffix(base, ".service"),
		strings.HasSuffix(base, ".scope"),
		strings.HasSuffix(base, ".socket"):
		return base
	}
	return ""
}

// UnitBasename returns "nginx" from "nginx.service".
func UnitBasename(unit string) string {
	unit = path.Base(unit)
	for _, suf := range []string{".service", ".scope", ".socket"} {
		if strings.HasSuffix(unit, suf) {
			return strings.TrimSuffix(unit, suf)
		}
	}
	return unit
}

// IsWatchedUnit reports whether unit matches any watched unit pattern.
// Patterns may be exact ("nginx.service") or prefix ("php") matching the
// unit basename without suffix.
func IsWatchedUnit(unit string, watched []string) bool {
	if unit == "" || len(watched) == 0 {
		return false
	}
	base := path.Base(unit)
	name := strings.ToLower(UnitBasename(base))
	baseLow := strings.ToLower(base)
	nameNorm := normalizeUnitName(name)
	for _, w := range watched {
		w = strings.TrimSpace(strings.ToLower(w))
		if w == "" {
			continue
		}
		wBase := UnitBasename(w)
		wNorm := normalizeUnitName(wBase)
		if baseLow == w || name == w || name == wBase || baseLow == wBase+".service" {
			return true
		}
		if strings.HasPrefix(name, w) || strings.HasPrefix(nameNorm, wNorm) {
			return true
		}
		// php8.3-fpm matches php-fpm after digit/dot stripping
		if wNorm != "" && (nameNorm == wNorm || strings.HasPrefix(nameNorm, wNorm) || strings.Contains(nameNorm, wNorm)) {
			return true
		}
	}
	return false
}

// normalizeUnitName strips digits and dots so php8.3-fpm ~ php-fpm.
func normalizeUnitName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' || r == '.' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// EnrichProcess fills ProcessContext cgroup/unit fields from pid.
func EnrichProcess(pid int, pc *procfs.Status) (cgroup, unit, anchorKey string) {
	_ = pc
	info := FromPID(pid)
	return info.CgroupPath, info.SystemdUnit, info.Anchor
}

// PIDString is a tiny helper for entity IDs.
func PIDString(pid int) string {
	return strconv.Itoa(pid)
}
