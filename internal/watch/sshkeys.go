package watch

import (
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"ghostcatcher/internal/detect/persistence"
)

// RunAuthorizedKeys triggers onWrite debounced callback when authorized_keys or .ssh dirs change (Linux inotify-backed via fsnotify).
func RunAuthorizedKeys(debounce time.Duration, onScan func() error, stop <-chan struct{}) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		slog.Error("fsnotify new watcher", "err", err)
		return
	}
	defer w.Close()

	paths, err := persistence.AuthorizedKeysPaths()
	if err != nil {
		slog.Error("authorized keys paths", "err", err)
		return
	}
	dirs := map[string]struct{}{}
	for _, p := range paths {
		d := filepath.Dir(p)
		dirs[d] = struct{}{}
	}
	for d := range dirs {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			_ = w.Add(d)
		}
	}
	// Also watch parent homes for .ssh creation
	for d := range dirs {
		parent := filepath.Dir(d)
		if st, err := os.Stat(parent); err == nil && st.IsDir() {
			_ = w.Add(parent)
		}
	}

	var mu sync.Mutex
	var timer *time.Timer
	schedule := func() {
		mu.Lock()
		defer mu.Unlock()
		if timer != nil {
			timer.Stop()
		}
		timer = time.AfterFunc(debounce, func() {
			_ = onScan()
		})
	}

	for {
		select {
		case <-stop:
			return
		case err := <-w.Errors:
			if err != nil {
				slog.Debug("fsnotify error", "err", err)
			}
		case ev, ok := <-w.Events:
			if !ok {
				return
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) == 0 {
				continue
			}
			base := filepath.Base(ev.Name)
			if base != "authorized_keys" && base != ".ssh" {
				continue
			}
			schedule()
		}
	}
}
