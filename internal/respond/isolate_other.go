//go:build !linux

package respond

import "fmt"

func (eng *Engine) isolateHost() error {
	return fmt.Errorf("isolate_host not supported on this platform")
}
