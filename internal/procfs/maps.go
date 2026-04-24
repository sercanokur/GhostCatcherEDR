package procfs

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// MapEntry is one line from /proc/pid/maps.
type MapEntry struct {
	Perms    string
	Pathname string
}

// ReadMaps parses /proc/[pid]/maps. Pathname may be empty for anonymous mappings.
func ReadMaps(pid int) ([]MapEntry, error) {
	f, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "maps"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []MapEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		perms := fields[1]
		pathname := ""
		if len(fields) > 5 {
			pathname = strings.Join(fields[5:], " ")
		}
		out = append(out, MapEntry{Perms: perms, Pathname: pathname})
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
