package sensor

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// auditdSource parses /var/log/audit/audit.log in tail-follow mode. This
// is deliberately dependency-free (no libaudit linkage) so that the agent
// remains a single statically-linked binary. Operators who want lower
// latency should run the eBPF backend instead.
type auditdSource struct {
	f    *os.File
	stop chan struct{}
}

func newAuditd(_ context.Context) (Source, error) {
	f, err := os.Open("/var/log/audit/audit.log")
	if err != nil {
		return nil, err
	}
	// Start at end-of-file; we only care about new events.
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return nil, err
	}
	return &auditdSource{f: f, stop: make(chan struct{})}, nil
}

func (a *auditdSource) Name() string { return "auditd" }

func (a *auditdSource) Start(ctx context.Context, out chan<- Event) error {
	r := bufio.NewReader(a.f)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-a.stop:
			return nil
		default:
		}
		line, err := r.ReadString('\n')
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		ev, ok := parseAuditLine(line)
		if !ok {
			continue
		}
		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		}
	}
}

func (a *auditdSource) Close() error {
	close(a.stop)
	return a.f.Close()
}

// parseAuditLine extracts a handful of well-known audit message types.
// Example: "type=SYSCALL msg=audit(...): syscall=59 success=yes exit=0 ..."
// The syscall number mapping is x86_64.
var syscallMap = map[int]Kind{
	59:  KindExec,        // execve
	322: KindExec,        // execveat
	257: KindOpenat,      // openat
	42:  KindConnect,     // connect
	101: KindPtrace,      // ptrace
	175: KindInitModule,  // init_module
	313: KindInitModule,  // finit_module
	319: KindMemfdCreate, // memfd_create
	50:  KindListen,      // listen
	41:  KindSocket,      // socket
	275: KindSplice,      // splice
}

func parseAuditLine(line string) (Event, bool) {
	if !strings.Contains(line, "type=SYSCALL") {
		return Event{}, false
	}
	fields := map[string]string{}
	for _, part := range strings.Fields(line) {
		if i := strings.IndexByte(part, '='); i > 0 {
			fields[part[:i]] = strings.Trim(part[i+1:], "\"")
		}
	}
	nr, _ := strconv.Atoi(fields["syscall"])
	kind, ok := syscallMap[nr]
	if !ok {
		return Event{}, false
	}
	pid, _ := strconv.Atoi(fields["pid"])
	ppid, _ := strconv.Atoi(fields["ppid"])
	uid64, _ := strconv.ParseUint(fields["uid"], 10, 32)
	ev := Event{
		Kind:      kind,
		When:      time.Now().UTC(),
		PID:       pid,
		PPID:      ppid,
		UID:       uint32(uid64),
		Comm:      fields["comm"],
		SyscallNR: nr,
	}
	// Audit prints syscall arguments as hex without the 0x prefix.
	// For socket() and splice() we capture them so downstream detectors
	// (e.g. CVE-2026-31431 / Copy Fail) can reason about the syscall
	// shape without needing kernel-side eBPF.
	if kind == KindSocket || kind == KindSplice {
		ev.Extra = map[string]string{}
		for _, k := range []string{"a0", "a1", "a2", "a3", "exit", "success"} {
			if v, ok := fields[k]; ok && v != "" {
				ev.Extra[k] = v
			}
		}
	}
	return ev, true
}

var _ = errors.New
