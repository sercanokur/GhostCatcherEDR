package procfs

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// MapEntry is one line from /proc/pid/maps. Pathname is "" for anonymous
// mappings; IsDeleted is true when the kernel marked the backing inode
// with the " (deleted)" suffix (classic "run from memory" footprint).
type MapEntry struct {
	Perms     string
	Pathname  string
	IsDeleted bool
}

// ReadMaps parses /proc/[pid]/maps.
func ReadMaps(pid int) ([]MapEntry, error) {
	f, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "maps"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []MapEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		perms := fields[1]
		pathname := ""
		deleted := false
		if len(fields) > 5 {
			pathname = strings.Join(fields[5:], " ")
			if strings.HasSuffix(pathname, "(deleted)") {
				deleted = true
				pathname = strings.TrimSpace(strings.TrimSuffix(pathname, "(deleted)"))
			}
		}
		out = append(out, MapEntry{Perms: perms, Pathname: pathname, IsDeleted: deleted})
	}
	return out, sc.Err()
}

// HasRWXSegment reports rwx segments excluding tiny vdso/vsyscall noise when labeled.
func HasRWXSegment(entries []MapEntry) (bool, string) {
	for _, e := range entries {
		if len(e.Perms) < 3 || e.Perms[0] != 'r' || e.Perms[1] != 'w' || e.Perms[2] != 'x' {
			continue
		}
		p := e.Pathname
		if strings.Contains(p, "[vdso]") || strings.Contains(p, "[vsyscall]") {
			continue
		}
		return true, p
	}
	return false, ""
}

// WorldWritableSegmentPathHints returns true if any mapping backs a file
// under typical world-writable dirs (/tmp, /dev/shm, /var/tmp). Such a
// mapping in a long-running network service is a strong memory-resident
// malware indicator.
func WorldWritableSegmentPathHints(entries []MapEntry) (bool, string) {
	prefixes := []string{"/tmp/", "/dev/shm/", "/var/tmp/", "/run/"}
	for _, e := range entries {
		for _, pref := range prefixes {
			if strings.HasPrefix(e.Pathname, pref) {
				return true, e.Pathname
			}
		}
	}
	return false, ""
}

// LoadedSharedObjects returns every distinct .so path mapped with exec
// permission; used by the baseline to learn the "allowed" library set for
// a long-running server process.
func LoadedSharedObjects(entries []MapEntry) []string {
	seen := map[string]struct{}{}
	for _, e := range entries {
		if len(e.Perms) < 3 || e.Perms[2] != 'x' {
			continue
		}
		if e.Pathname == "" || strings.HasPrefix(e.Pathname, "[") {
			continue
		}
		if !(strings.HasSuffix(e.Pathname, ".so") ||
			strings.Contains(e.Pathname, ".so.")) {
			continue
		}
		seen[e.Pathname] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	return out
}

// HasDeletedExecSegment flags a process whose code segment refers to an
// unlinked file (classic fileless malware after the loader deletes its own
// dropper). Anonymous mappings are ignored.
func HasDeletedExecSegment(entries []MapEntry) (bool, string) {
	for _, e := range entries {
		if !e.IsDeleted || e.Pathname == "" {
			continue
		}
		if len(e.Perms) >= 3 && e.Perms[2] == 'x' {
			return true, e.Pathname
		}
	}
	return false, ""
}
