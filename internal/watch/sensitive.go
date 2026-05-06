package watch

import (
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// SensitivePathSpec expresses a watch target. Path may point at a file or a
// directory; when Recursive is true and Path is a dir, every existing
// subdirectory is registered and future mkdirs trigger a re-add.
type SensitivePathSpec struct {
	Path      string
	Recursive bool
	// FilenameFilter, when non-nil, is called for every event and must return
	// true for the event to trigger a rescan. Useful to narrow noisy dirs.
	FilenameFilter func(name string) bool
}

// DefaultSensitivePaths returns the canonical "anything under here changes =
// rescan now" list. The agent still scans on schedule; this list exists to
// shrink detection latency to near-zero for the most attacker-targeted paths.
//
// Non-existent entries are silently skipped by the watcher loop so the list
// can be shared across distros.
func DefaultSensitivePaths(documentRoots []string) []SensitivePathSpec {
	specs := []SensitivePathSpec{
		// Preload-style code injection.
		{Path: "/etc/ld.so.preload"},
		{Path: "/etc/ld.so.conf"},
		{Path: "/etc/ld.so.conf.d", Recursive: true},

		// Cron / periodic surfaces.
		{Path: "/etc/crontab"},
		{Path: "/etc/anacrontab"},
		{Path: "/etc/cron.d", Recursive: true},
		{Path: "/etc/cron.hourly", Recursive: true},
		{Path: "/etc/cron.daily", Recursive: true},
		{Path: "/etc/cron.weekly", Recursive: true},
		{Path: "/etc/cron.monthly", Recursive: true},
		{Path: "/var/spool/cron", Recursive: true},
		{Path: "/var/spool/at", Recursive: true},
		{Path: "/var/spool/atjobs", Recursive: true},

		// systemd unit surfaces.
		{Path: "/etc/systemd/system", Recursive: true},
		{Path: "/lib/systemd/system", Recursive: true},
		{Path: "/usr/lib/systemd/system", Recursive: true},
		{Path: "/run/systemd/system", Recursive: true},

		// Sudoers + PAM + SSH daemon.
		{Path: "/etc/sudoers"},
		{Path: "/etc/sudoers.d", Recursive: true},
		{Path: "/etc/pam.d", Recursive: true},
		{Path: "/etc/ssh/sshd_config"},
		{Path: "/etc/ssh/sshd_config.d", Recursive: true},

		// User database.
		{Path: "/etc/passwd"},
		{Path: "/etc/shadow"},
		{Path: "/etc/group"},

		// Kernel module load on boot.
		{Path: "/etc/modules"},
		{Path: "/etc/modules-load.d", Recursive: true},
		{Path: "/etc/modprobe.d", Recursive: true},
	}
	for _, root := range documentRoots {
		specs = append(specs, SensitivePathSpec{
			Path:      root,
			Recursive: true,
			FilenameFilter: func(name string) bool {
				// Reduce noise from typical dev tooling: only rescan on script-ish files.
				for _, ext := range []string{".php", ".phtml", ".phar", ".inc", ".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".cfm", ".pl", ".cgi", ".py"} {
					if len(name) >= len(ext) && name[len(name)-len(ext):] == ext {
						return true
					}
				}
				return false
			},
		})
	}
	return specs
}

// RunSensitive watches every spec and calls onScan (debounced) any time
// one of them changes. It is a blocking call; stop via the stop channel.
func RunSensitive(specs []SensitivePathSpec, debounce time.Duration, onScan func() error, stop <-chan struct{}) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		slog.Error("fsnotify new watcher", "err", err)
		return
	}
	defer w.Close()

	register := func(dir string) {
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			return
		}
		_ = w.Add(dir)
	}
	for _, s := range specs {
		st, err := os.Stat(s.Path)
		if err != nil {
			// Also watch parent so a future create of the missing path fires.
			register(filepath.Dir(s.Path))
			continue
		}
		if !st.IsDir() {
			register(filepath.Dir(s.Path))
			continue
		}
		if s.Recursive {
			_ = filepath.WalkDir(s.Path, func(p string, d fs.DirEntry, err error) error {
				if err == nil && d.IsDir() {
					register(p)
				}
				return nil
			})
		} else {
			register(s.Path)
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

	interesting := fsnotify.Write | fsnotify.Create | fsnotify.Remove | fsnotify.Rename | fsnotify.Chmod

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
			if ev.Op&interesting == 0 {
				continue
			}
			// If a new directory was created under a recursive watch, add it.
			if ev.Op&fsnotify.Create != 0 {
				if st, err := os.Stat(ev.Name); err == nil && st.IsDir() {
					register(ev.Name)
				}
			}
			// Apply filters for noisy dirs like document_roots.
			name := filepath.Base(ev.Name)
			keep := true
			for _, s := range specs {
				if s.FilenameFilter != nil && filepath.Dir(ev.Name) == s.Path {
					if !s.FilenameFilter(name) {
						keep = false
						break
					}
				}
			}
			if !keep {
				continue
			}
			schedule()
		}
	}
}
