package baseline

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCache_ReloadsOnMtimeChange(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "b.json")
	s := EmptySnapshot()
	s.WebFiles["/a.php"] = WebFileRecord{SHA256: "one", Mtime: time.Unix(1, 0).UTC(), Size: 3}
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}

	var c Cache
	first, err := c.Get(p)
	if err != nil {
		t.Fatal(err)
	}
	if first.WebFiles["/a.php"].SHA256 != "one" {
		t.Fatal(first.WebFiles["/a.php"])
	}
	second, err := c.Get(p)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("expected same cached pointer")
	}

	time.Sleep(20 * time.Millisecond)
	s.WebFiles["/a.php"] = WebFileRecord{SHA256: "two", Mtime: time.Unix(2, 0).UTC(), Size: 4}
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	third, err := c.Get(p)
	if err != nil {
		t.Fatal(err)
	}
	if third.WebFiles["/a.php"].SHA256 != "two" {
		t.Fatalf("got %q", third.WebFiles["/a.php"].SHA256)
	}
}

func TestCache_MissingFile(t *testing.T) {
	var c Cache
	p := filepath.Join(t.TempDir(), "missing.json")
	a, err := c.Get(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Get(p)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("expected cached empty snapshot")
	}
	if a.IsCommitted() {
		t.Fatal("empty should be uncommitted")
	}
	_ = os.WriteFile(p, []byte(`{"version":1}`), 0o600)
}
