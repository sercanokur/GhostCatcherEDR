package procfs

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ReadStartTime returns the kernel starttime field from /proc/[pid]/stat
// (clock ticks since boot). Combined with PID it uniquely identifies a
// process instance across PID reuse.
func ReadStartTime(pid int) (uint64, error) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	s := string(b)
	// comm can contain spaces and parentheses; fields after the closing
	// paren of "(comm)" are space-separated. starttime is field 22 of the
	// full stat record = index 19 after the closing paren (0-based).
	idx := strings.LastIndexByte(s, ')')
	if idx < 0 || idx+2 >= len(s) {
		return 0, fmt.Errorf("procfs: malformed stat for pid %d", pid)
	}
	fields := strings.Fields(s[idx+2:])
	if len(fields) < 20 {
		return 0, fmt.Errorf("procfs: short stat for pid %d", pid)
	}
	return strconv.ParseUint(fields[19], 10, 64)
}
