package procfs

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Status is a parsed selection of /proc/pid/status fields useful for
// detection. Empty fields simply mean "not observed in this status file".
type Status struct {
	Name      string
	TracerPid int
	RealUID   int
	EffUID    int
	CapEff    string // hex string, e.g. "000001ffffffffff"
	CapInh    string
	CapPrm    string
}

// ReadStatus returns the parsed /proc/[pid]/status. Missing fields are
// tolerated: the caller must treat zero/empty values as "unknown".
func ReadStatus(pid int) (Status, error) {
	var s Status
	f, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return s, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "Name:"):
			s.Name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		case strings.HasPrefix(line, "TracerPid:"):
			if v, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "TracerPid:"))); err == nil {
				s.TracerPid = v
			}
		case strings.HasPrefix(line, "Uid:"):
			f := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(f) >= 2 {
				s.RealUID, _ = strconv.Atoi(f[0])
				s.EffUID, _ = strconv.Atoi(f[1])
			}
		case strings.HasPrefix(line, "CapEff:"):
			s.CapEff = strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		case strings.HasPrefix(line, "CapInh:"):
			s.CapInh = strings.TrimSpace(strings.TrimPrefix(line, "CapInh:"))
		case strings.HasPrefix(line, "CapPrm:"):
			s.CapPrm = strings.TrimSpace(strings.TrimPrefix(line, "CapPrm:"))
		}
	}
	return s, sc.Err()
}

// ReadCgroup returns the cgroup lines for a pid (first line is usually
// enough on cgroup v1/v2 hybrid hosts). Used to classify a process as
// Docker/containerd/k8s/LXC and derive a container_id.
func ReadCgroup(pid int) (string, error) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return "", err
	}
	return string(b), nil
}
