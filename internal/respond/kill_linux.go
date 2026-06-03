//go:build linux

package respond

import (
	"fmt"
	"strconv"
	"strings"
	"syscall"
)

func (eng *Engine) killProcess(target string) error {
	pid, err := parsePIDTarget(target)
	if err != nil {
		return err
	}
	if pid <= 1 {
		return fmt.Errorf("refusing to kill pid %d", pid)
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		return err
	}
	return nil
}

func parsePIDTarget(target string) (int, error) {
	target = strings.TrimSpace(target)
	if strings.HasPrefix(target, "pid:") {
		target = strings.TrimPrefix(target, "pid:")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(target))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("invalid pid target %q", target)
	}
	return pid, nil
}
