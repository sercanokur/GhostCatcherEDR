package web

import (
	"io/fs"
	"time"

	"ghostcatcher/internal/baseline"
)

// baselineMetaMatches reports whether on-disk mtime (+ size when known)
// still matches the committed WebFileRecord, so content reads can be skipped.
func baselineMetaMatches(st fs.FileInfo, rec baseline.WebFileRecord) bool {
	if rec.SHA256 == "" || st == nil {
		return false
	}
	// JSON timestamps are second-precision in practice; truncate both sides.
	if !st.ModTime().UTC().Truncate(time.Second).Equal(rec.Mtime.UTC().Truncate(time.Second)) {
		return false
	}
	if rec.Size > 0 && st.Size() != rec.Size {
		return false
	}
	return true
}
