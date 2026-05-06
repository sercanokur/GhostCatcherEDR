package emit

import (
	"path/filepath"
	"testing"
)

func TestSpool_AppendDrain(t *testing.T) {
	dir := t.TempDir()
	sp, err := NewSpool(dir, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if err := sp.Append([]byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := sp.Append([]byte(`{"b":2}`)); err != nil {
		t.Fatal(err)
	}
	recs, err := sp.Drain()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 2 records, got %d", len(recs))
	}
	_ = sp.Close()
	_ = filepath.Join(dir, "events.ndjson")
}

func TestLimiter_RateCap(t *testing.T) {
	l := NewLimiter(3)
	for i := 0; i < 3; i++ {
		if !l.Allow("R1") {
			t.Fatal("expected allow")
		}
	}
	if l.Allow("R1") {
		t.Fatal("expected drop")
	}
	if !l.Allow("R2") {
		t.Fatal("different rule should not share budget")
	}
}
