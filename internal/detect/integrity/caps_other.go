//go:build !linux

package integrity

// readFileCapability returns "" on non-Linux hosts (xattrs are Linux-only).
// The agent still runs its SUID walker there; capability detection is simply
// a no-op.
func readFileCapability(path string) string {
	return ""
}
