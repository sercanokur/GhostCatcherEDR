package procfs

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Processes returns numeric PIDs under /proc.
func Processes() ([]int, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

// Comm returns executable basename for pid (from /proc/pid/comm).
func Comm(pid int) (string, error) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// Cmdline returns argv[0].. joined with nulls stripped for reading first arg.
func Cmdline(pid int) ([]string, error) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimRight(string(b), "\x00"), string(byte(0))), nil
}

// Environ reads /proc/pid/environ as KEY=value map (best effort).
func Environ(pid int) (map[string]string, error) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "environ"))
	if err != nil {
		return nil, err
	}
	out := make(map[string]string)
	for _, part := range bytes.Split(b, []byte{0}) {
		if len(part) == 0 {
			continue
		}
		i := bytes.IndexByte(part, '=')
		if i <= 0 {
			continue
		}
		out[string(part[:i])] = string(part[i+1:])
	}
	return out, nil
}

// Children returns direct child PIDs from /proc/pid/task/*/children (Linux 4.13+).
func Children(pid int) ([]int, error) {
	pattern := filepath.Join("/proc", strconv.Itoa(pid), "task", "*", "children")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return childrenViaScan(pid)
	}
	var kids []int
	seen := map[int]struct{}{}
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		fields := strings.Fields(string(b))
		for _, f := range fields {
			c, err := strconv.Atoi(f)
			if err != nil {
				continue
			}
			if _, ok := seen[c]; !ok {
				seen[c] = struct{}{}
				kids = append(kids, c)
			}
		}
	}
	if len(kids) > 0 {
		return kids, nil
	}
	return childrenViaScan(pid)
}

func childrenViaScan(parent int) ([]int, error) {
	pids, err := Processes()
	if err != nil {
		return nil, err
	}
	var out []int
	for _, pid := range pids {
		if pid == parent {
			continue
		}
		ppid, err := PPid(pid)
		if err != nil {
			continue
		}
		if ppid == parent {
			out = append(out, pid)
		}
	}
	return out, nil
}

// PPid reads parent pid from /proc/pid/status.
func PPid(pid int) (int, error) {
	f, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return 0, fmt.Errorf("bad status")
			}
			return strconv.Atoi(fields[1])
		}
	}
	return 0, fmt.Errorf("ppid not found")
}

// ResolveExe returns symlink target of /proc/pid/exe if readable.
func ResolveExe(pid int) string {
	p := filepath.Join("/proc", strconv.Itoa(pid), "exe")
	target, err := os.Readlink(p)
	if err != nil {
		return ""
	}
	return target
}
