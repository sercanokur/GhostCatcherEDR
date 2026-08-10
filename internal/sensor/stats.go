package sensor

import (
	"context"
	"log/slog"
	"strconv"
	"sync/atomic"
	"time"
)

// Stats holds process-wide sensor backpressure counters.
type Stats struct {
	ChannelDrop    atomic.Uint64
	RingbufOverrun atomic.Uint64
	Emitted        atomic.Uint64
}

// Global is the shared sensor counter set used by all backends.
var Global Stats

// TryEmit sends ev without blocking. On a full channel it increments
// ChannelDrop and returns false so producers (especially eBPF) never stall
// the kernel ringbuffer drain loop.
func TryEmit(ctx context.Context, out chan<- Event, ev Event) bool {
	select {
	case <-ctx.Done():
		return false
	case out <- ev:
		Global.Emitted.Add(1)
		return true
	default:
		n := Global.ChannelDrop.Add(1)
		if n == 1 || n%1000 == 0 {
			slog.Warn("sensor.channel_drop",
				"total", n,
				"kind", ev.Kind,
			)
		}
		return false
	}
}

// NoteRingbufOverrun records a kernel ringbuffer read/lost-sample error.
func NoteRingbufOverrun(err error) {
	n := Global.RingbufOverrun.Add(1)
	if n == 1 || n%100 == 0 {
		slog.Warn("ringbuffer.overrun", "total", n, "err", err)
	}
}

// Snapshot returns a point-in-time copy of counters.
func (s *Stats) Snapshot() (emitted, drop, overrun uint64) {
	return s.Emitted.Load(), s.ChannelDrop.Load(), s.RingbufOverrun.Load()
}

// Debouncer coalesces duplicate sensor events within a window so a noisy
// host does not flood the OODA fast path (config: sensor.debounce_ms).
type Debouncer struct {
	window time.Duration
	last   map[string]time.Time
}

// NewDebouncer returns nil when window <= 0 (debounce disabled).
func NewDebouncer(window time.Duration) *Debouncer {
	if window <= 0 {
		return nil
	}
	return &Debouncer{window: window, last: make(map[string]time.Time)}
}

// Allow reports whether ev should be processed now.
func (d *Debouncer) Allow(ev Event) bool {
	if d == nil {
		return true
	}
	key := string(ev.Kind) + "|" + strconv.Itoa(ev.PID) + "|" + ev.Path + "|" + ev.Comm + "|" + ev.RemoteIP
	now := time.Now()
	if t, ok := d.last[key]; ok && now.Sub(t) < d.window {
		return false
	}
	d.last[key] = now
	if len(d.last) > 4096 {
		cutoff := now.Add(-d.window)
		for k, t := range d.last {
			if t.Before(cutoff) {
				delete(d.last, k)
			}
		}
	}
	return true
}
