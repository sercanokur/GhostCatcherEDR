package sensor

import (
	"context"
	"time"

	"ghostcatcher/internal/procfs"
)

// procPoll is the last-resort sensor. Every interval it enumerates
// /proc, diffs against the previous snapshot, and emits synthetic exec
// events for any new PID. It is intentionally low rate so it can live
// side-by-side with a real eBPF sensor without being noisy.
type procPoll struct {
	interval time.Duration
	stop     chan struct{}
}

func newProcPoll(_ context.Context) (Source, error) {
	return &procPoll{interval: 2 * time.Second, stop: make(chan struct{})}, nil
}

func (p *procPoll) Name() string { return "proc-poll" }

func (p *procPoll) Start(ctx context.Context, out chan<- Event) error {
	prev := map[int]struct{}{}
	if pids, err := procfs.Processes(); err == nil {
		for _, pid := range pids {
			prev[pid] = struct{}{}
		}
	}
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-p.stop:
			return nil
		case <-t.C:
		}
		pids, err := procfs.Processes()
		if err != nil {
			continue
		}
		cur := make(map[int]struct{}, len(pids))
		for _, pid := range pids {
			cur[pid] = struct{}{}
			if _, seen := prev[pid]; seen {
				continue
			}
			comm, _ := procfs.Comm(pid)
			argv, _ := procfs.Cmdline(pid)
			ppid, _ := procfs.PPid(pid)
			select {
			case out <- Event{
				Kind: KindExec, When: time.Now().UTC(),
				PID: pid, PPID: ppid, Comm: comm, Argv: argv,
			}:
			case <-ctx.Done():
				return nil
			}
		}
		prev = cur
	}
}

func (p *procPoll) Close() error {
	close(p.stop)
	return nil
}
