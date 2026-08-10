package baseline

import (
	"os"
	"sync"
	"time"
)

// Cache reloads a baseline Snapshot only when the on-disk file mtime/size
// changes. Concurrent Get calls share one loaded snapshot.
type Cache struct {
	mu      sync.Mutex
	path    string
	modTime time.Time
	size    int64
	missing bool
	snap    *Snapshot
}

// Get returns the cached snapshot for path, reading from disk only on miss
// or when the file metadata changes. A missing file yields EmptySnapshot
// (same as Load) and is cached until the path appears.
func (c *Cache) Get(path string) (*Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	st, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		if c.snap != nil && c.path == path && c.missing {
			return c.snap, nil
		}
		c.path = path
		c.modTime = time.Time{}
		c.size = 0
		c.missing = true
		c.snap = EmptySnapshot()
		return c.snap, nil
	}
	if c.snap != nil && c.path == path && !c.missing &&
		c.modTime.Equal(st.ModTime()) && c.size == st.Size() {
		return c.snap, nil
	}
	snap, err := Load(path)
	if err != nil {
		return nil, err
	}
	c.path = path
	c.modTime = st.ModTime()
	c.size = st.Size()
	c.missing = false
	c.snap = snap
	return snap, nil
}

// Invalidate drops the cached snapshot so the next Get reloads from disk.
func (c *Cache) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.snap = nil
	c.path = ""
	c.missing = false
}
