package web

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"ghostcatcher/internal/baseline"
)

func TestBaselineMetaMatches(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.php")
	if err := os.WriteFile(p, []byte("<?php echo 1;"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	rec := baseline.WebFileRecord{
		SHA256: "abc",
		Mtime:  st.ModTime().UTC(),
		Size:   st.Size(),
	}
	if !baselineMetaMatches(st, rec) {
		t.Fatal("expected match")
	}
	rec.Size++
	if baselineMetaMatches(st, rec) {
		t.Fatal("size mismatch should fail")
	}
	rec.Size = st.Size()
	rec.Mtime = st.ModTime().UTC().Add(-time.Hour)
	if baselineMetaMatches(st, rec) {
		t.Fatal("mtime mismatch should fail")
	}
	rec.Mtime = st.ModTime().UTC()
	rec.SHA256 = ""
	if baselineMetaMatches(st, rec) {
		t.Fatal("empty sha should fail")
	}
}
