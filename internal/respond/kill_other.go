//go:build !linux

package respond

import "fmt"

func (eng *Engine) killProcess(target string) error {
	return fmt.Errorf("kill_process not supported on this platform (target=%s)", target)
}
