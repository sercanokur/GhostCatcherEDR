package budget

import (
	"testing"
	"time"
)

func TestObserveScanAndCounters(t *testing.T) {
	before := Get()
	AddProcRead(3)
	AddHashBytes(100)
	ObserveScan("full", 10*time.Millisecond, Extra{OverlappingSkipped: 2})
	after := Get()
	if after.ProcReads < before.ProcReads+3 {
		t.Fatalf("proc_reads %d → %d", before.ProcReads, after.ProcReads)
	}
	if after.HashBytes < before.HashBytes+100 {
		t.Fatalf("hash_bytes %d → %d", before.HashBytes, after.HashBytes)
	}
	if after.ScanCount < before.ScanCount+1 {
		t.Fatal("scan_count not incremented")
	}
	if after.LastScanMs < 0 {
		t.Fatal("last scan ms")
	}
}
