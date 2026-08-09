package procfs

import (
	"os"
	"testing"
)

func TestReadStartTime_Self(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no /proc — not a Linux procfs host")
	}
	st, err := ReadStartTime(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if st == 0 {
		t.Fatal("starttime unexpectedly 0")
	}
	// Stable across re-reads for the same process.
	st2, err := ReadStartTime(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if st != st2 {
		t.Fatalf("starttime drifted %d → %d", st, st2)
	}
}
