package persistence

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// fileSHA returns a hex-encoded SHA-256 digest for path, or "" on any error.
// The scanners in this package use "" as a sentinel for "read failed / not
// present" and emit no event in that case.
func fileSHA(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// walkFiles returns every regular file under root whose basename matches
// one of the extensions (or all files when extensions is empty). Non-dir
// roots are skipped; IO errors are swallowed so scanners can still run on
// hosts that lack specific paths.
func walkFiles(root string, extensions ...string) []string {
	st, err := os.Stat(root)
	if err != nil || !st.IsDir() {
		return nil
	}
	var out []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if len(extensions) == 0 {
			out = append(out, p)
			return nil
		}
		low := strings.ToLower(p)
		for _, e := range extensions {
			if strings.HasSuffix(low, e) {
				out = append(out, p)
				return nil
			}
		}
		return nil
	})
	return out
}

// recordPersistenceBaseline stores (path -> sha256) in the snapshot
// baseline for later delta detection. Missing/unreadable files are skipped.
func recordPersistenceBaseline(snapMap map[string]string, paths []string) {
	for _, p := range paths {
		if h := fileSHA(p); h != "" {
			snapMap[p] = h
		}
	}
}
