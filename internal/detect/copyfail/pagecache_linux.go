//go:build linux

package copyfail

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// pageCacheVsDiskHash returns sha256 hashes of the file as currently
// served from the kernel page cache, and as fetched fresh from disk
// after the cached pages have been dropped. The third return is false
// when the path does not exist or is unreadable; both hashes are
// otherwise hex strings.
//
// The "drop the cache" step uses posix_fadvise(POSIX_FADV_DONTNEED),
// which removes the file's pages from the page cache without unlinking
// the file or truncating it. After the call, the next read repopulates
// the cache from the on-disk content. If an attacker has poisoned the
// cache via the algif_aead AEAD primitive (CVE-2026-31431), the two
// hashes will differ.
//
// Errors from posix_fadvise are non-fatal: on filesystems that do not
// honour DONTNEED (rare, but possible for tmpfs / overlayfs in some
// configurations) the second read will simply re-hit the same cached
// pages and the function returns equal hashes — i.e. a false negative,
// never a false positive.
func pageCacheVsDiskHash(path string) (cacheHash, diskHash string, ok bool, err error) {
	cacheHash, err = hashFile(path)
	if err != nil {
		return "", "", false, err
	}
	if f, ferr := os.Open(path); ferr == nil {
		_ = unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED)
		_ = f.Close()
	}
	diskHash, err = hashFile(path)
	if err != nil {
		return "", "", false, err
	}
	return cacheHash, diskHash, true, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
