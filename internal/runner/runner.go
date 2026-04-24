package runner

import (
	"io"
	"log/slog"
	"os"
	"time"

	"ghostcatcher/internal/baseline"
	"ghostcatcher/internal/config"
	"ghostcatcher/internal/detect/integrity"
	"ghostcatcher/internal/detect/ldpreload"
	"ghostcatcher/internal/detect/memorymaps"
	"ghostcatcher/internal/detect/persistence"
	"ghostcatcher/internal/detect/web"
	"ghostcatcher/internal/event"
	"ghostcatcher/internal/export/syslog"
	"ghostcatcher/internal/rules"
	"ghostcatcher/internal/watch"
)

const AgentVersion = "0.1.0"

type Runner struct {
	cfg       *config.Config
	pack      *rules.Pack
	out       io.Writer
	syslog    *syslog.Client
	lastDedup map[string]time.Time
}

func New(cfg *config.Config, pack *rules.Pack) *Runner {
	r := &Runner{
		cfg:       cfg,
		pack:      pack,
		out:       os.Stdout,
		lastDedup: make(map[string]time.Time),
	}
	if cfg.SyslogUDP.Enabled {
		sc, err := syslog.NewUDP(syslog.Config{
			Enabled:     true,
			Host:        cfg.SyslogUDP.Host,
			Port:        cfg.SyslogUDP.Port,
			Format:      cfg.SyslogUDP.Format,
			Facility:    cfg.SyslogUDP.Facility,
			AppName:     cfg.SyslogUDP.AppName,
			Hostname:    cfg.SyslogUDP.Hostname,
			ProcID:      cfg.SyslogUDP.ProcID,
			MaxMsgBytes: cfg.SyslogUDP.MaxMsgBytes,
		})
		if err != nil {
			slog.Warn("syslog UDP disabled: init failed", "err", err)
		} else {
			r.syslog = sc
		}
	}
	return r
}

func (r *Runner) WithOutput(w io.Writer) *Runner {
	r.out = w
	return r
}

func (r *Runner) RunOnce() error {
	snap, err := baseline.Load(r.cfg.BaselinePath)
	if err != nil {
		return err
	}
	var all []event.Event
	ev, err := persistence.Scan(r.cfg, snap, r.pack, AgentVersion)
	if err != nil {
		return err
	}
	all = append(all, ev...)

	ev2, err := ldpreload.Scan(r.cfg, snap, r.pack, AgentVersion)
	if err != nil {
		return err
	}
	all = append(all, ev2...)

	evInt, err := integrity.Scan(r.cfg, snap, r.pack, AgentVersion)
	if err != nil {
		return err
	}
	all = append(all, evInt...)

	evMap, err := memorymaps.Scan(r.cfg, snap, r.pack, AgentVersion)
	if err != nil {
		return err
	}
	all = append(all, evMap...)

	evRecon, err := web.ScanReconChildren(r.cfg, snap, r.pack, AgentVersion)
	if err != nil {
		return err
	}
	all = append(all, evRecon...)

	ev3, err := web.Scan(r.cfg, snap, r.pack, AgentVersion)
	if err != nil {
		return err
	}
	all = append(all, ev3...)

	for i := range all {
		e := &all[i]
		e.NormalizeDedup()
		if e.LearningOnly {
			r.emit(e)
			continue
		}
		if e.Confidence < r.cfg.MinConfidenceAlert {
			r.emit(e)
			continue
		}
		if r.shouldDedup(e.DedupKey) {
			continue
		}
		r.emit(e)
	}
	return nil
}

func (r *Runner) shouldDedup(key string) bool {
	if key == "" {
		return false
	}
	if t, ok := r.lastDedup[key]; ok && time.Since(t) < r.cfg.ScanInterval.Duration() {
		return true
	}
	r.lastDedup[key] = time.Now()
	return false
}

func (r *Runner) emit(e *event.Event) {
	b, err := e.JSONLine()
	if err != nil {
		return
	}
	_, _ = r.out.Write(append(b, '\n'))
	if r.syslog != nil {
		if err := r.syslog.Send(e, b); err != nil {
			slog.Debug("syslog udp send failed", "err", err)
		}
	}
}

// RunLoop blocks, running scans on interval until ctx cancelled - caller can use signal.
func (r *Runner) RunLoop(stop <-chan struct{}) {
	if r.cfg.WatchAuthorizedKeys {
		go watch.RunAuthorizedKeys(r.cfg.WatchDebounce.Duration(), func() error { return r.RunOnce() }, stop)
	}
	t := time.NewTicker(r.cfg.ScanInterval.Duration())
	defer t.Stop()
	_ = r.RunOnce()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			_ = r.RunOnce()
		}
	}
}
