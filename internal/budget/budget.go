// Package budget tracks lightweight host-impact counters for scans and I/O.
package budget

import (
	"log/slog"
	"sync/atomic"
	"time"
)

var (
	scanCount   atomic.Uint64
	lastScanMs  atomic.Int64
	procReads   atomic.Uint64
	hashBytes   atomic.Uint64
	scansLogged atomic.Uint64
)

// Extra carries optional counters from other packages (e.g. sensor) so
// budget stays dependency-free.
type Extra struct {
	OverlappingSkipped uint64
	SensorEmitted      uint64
	SensorDrop         uint64
	RingbufOverrun     uint64
}

// ObserveScan records a completed scan's wall time and periodically logs
// a host-budget line for operators (journalctl -g scan.budget).
func ObserveScan(kind string, d time.Duration, x Extra) {
	ms := d.Milliseconds()
	scanCount.Add(1)
	lastScanMs.Store(ms)
	n := scansLogged.Add(1)
	if n == 1 || n%10 == 0 || ms >= 500 {
		slog.Info("scan.budget",
			"kind", kind,
			"duration_ms", ms,
			"overlapping_skipped", x.OverlappingSkipped,
			"proc_reads", procReads.Load(),
			"hash_bytes", hashBytes.Load(),
			"sensor_emitted", x.SensorEmitted,
			"sensor_channel_drop", x.SensorDrop,
			"ringbuffer_overrun", x.RingbufOverrun,
		)
	}
}

// AddProcRead increments the /proc (and related) read counter.
func AddProcRead(n uint64) {
	if n > 0 {
		procReads.Add(n)
	}
}

// AddHashBytes increments bytes hashed/read for content scanning.
func AddHashBytes(n int64) {
	if n > 0 {
		hashBytes.Add(uint64(n))
	}
}

// Snapshot is a point-in-time view of host budget counters.
type Snapshot struct {
	ScanCount  uint64 `json:"scan_count"`
	LastScanMs int64  `json:"last_scan_duration_ms"`
	ProcReads  uint64 `json:"proc_reads"`
	HashBytes  uint64 `json:"hash_bytes"`
}

// Get returns the current counters.
func Get() Snapshot {
	return Snapshot{
		ScanCount:  scanCount.Load(),
		LastScanMs: lastScanMs.Load(),
		ProcReads:  procReads.Load(),
		HashBytes:  hashBytes.Load(),
	}
}
