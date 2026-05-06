//go:build linux

package integrity

import (
	"encoding/hex"

	"golang.org/x/sys/unix"
)

// readFileCapability returns a hex-encoded `security.capability` xattr value
// for path, or "" if the xattr is absent or unreadable. The raw bytes are
// hashed as the map value so any change (including flag bit changes) shows
// up as a delta.
func readFileCapability(path string) string {
	size, err := unix.Getxattr(path, "security.capability", nil)
	if err != nil || size <= 0 {
		return ""
	}
	buf := make([]byte, size)
	n, err := unix.Getxattr(path, "security.capability", buf)
	if err != nil || n <= 0 {
		return ""
	}
	return hex.EncodeToString(buf[:n])
}
