package selfguard

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestBinaryMatches_OK(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bin")
	if err := os.WriteFile(p, []byte("abc"), 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("abc"))
	if err := BinaryMatches(p, hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
}

func TestBinaryMatches_Mismatch(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bin")
	if err := os.WriteFile(p, []byte("abc"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := BinaryMatches(p, "00")
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if _, ok := err.(*MismatchError); !ok {
		t.Fatalf("expected MismatchError got %T", err)
	}
}
