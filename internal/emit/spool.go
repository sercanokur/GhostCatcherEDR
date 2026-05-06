package emit

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Spool is an append-only newline-delimited JSON buffer on disk. Events
// that failed to deliver to a live sink are written here and replayed the
// next time the sink accepts traffic.
//
// The spool is intentionally simple: a single file capped at maxBytes,
// rotated to .old when full so the hottest recent events survive.
type Spool struct {
	mu       sync.Mutex
	dir      string
	filename string
	maxBytes int64
	f        *os.File
}

// NewSpool opens (or creates) the spool file under dir.
func NewSpool(dir string, maxBytes int64) (*Spool, error) {
	if dir == "" {
		return nil, fmt.Errorf("spool dir required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Spool{
		dir:      dir,
		filename: filepath.Join(dir, "events.ndjson"),
		maxBytes: maxBytes,
	}
	f, err := os.OpenFile(s.filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	s.f = f
	return s, nil
}

// Append writes one newline-delimited JSON record. Rotates the file when
// maxBytes is exceeded so unbounded disk growth is impossible.
func (s *Spool) Append(line []byte) error {
	if s == nil || s.f == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.rotateIfNeeded(len(line) + 1); err != nil {
		return err
	}
	if _, err := s.f.Write(line); err != nil {
		return err
	}
	_, err := s.f.Write([]byte("\n"))
	return err
}

func (s *Spool) rotateIfNeeded(incoming int) error {
	if s.maxBytes <= 0 {
		return nil
	}
	st, err := s.f.Stat()
	if err != nil {
		return err
	}
	if st.Size()+int64(incoming) < s.maxBytes {
		return nil
	}
	// rotate: close, rename to .old, open fresh
	_ = s.f.Close()
	rotated := s.filename + ".old"
	_ = os.Remove(rotated)
	if err := os.Rename(s.filename, rotated); err != nil {
		return err
	}
	f, err := os.OpenFile(s.filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	s.f = f
	return nil
}

// Drain reads the entire spool file into memory, empties it, and returns
// every stored record so the caller can replay them. Intended for
// periodic "attempt to flush backlog" ticks.
func (s *Spool) Drain() ([][]byte, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.f.Close(); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(s.filename)
	if err != nil {
		return nil, err
	}
	if err := os.Truncate(s.filename, 0); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(s.filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	s.f = f
	var out [][]byte
	var start int
	for i, b := range data {
		if b == '\n' {
			if i > start {
				line := make([]byte, i-start)
				copy(line, data[start:i])
				out = append(out, line)
			}
			start = i + 1
		}
	}
	return out, nil
}

// Close flushes and closes the spool file. Safe to call multiple times.
func (s *Spool) Close() error {
	if s == nil || s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}

// Age returns how long ago the spool was last written to. Returns 0 when
// the spool is empty or unreadable.
func (s *Spool) Age() time.Duration {
	st, err := os.Stat(s.filename)
	if err != nil {
		return 0
	}
	return time.Since(st.ModTime())
}

// Ensure io.Writer compatibility for code paths that want a quick append.
var _ io.Closer = (*Spool)(nil)
