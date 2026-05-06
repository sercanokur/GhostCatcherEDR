//go:build !linux

package copyfail

// pageCacheVsDiskHash is a no-op on non-Linux hosts. Copy Fail is a
// Linux kernel flaw and the posix_fadvise(POSIX_FADV_DONTNEED) trick
// only works on Linux, so we silently return ok=false on macOS / *BSD
// dev environments. The agent still builds and runs there for tests.
func pageCacheVsDiskHash(_ string) (cacheHash, diskHash string, ok bool, err error) {
	return "", "", false, nil
}
