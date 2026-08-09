package sensor

import (
	"bufio"
	"context"
	"io"
	"net"
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
		Extra:     map[string]string{},
	}
	if exe := fields["exe"]; exe != "" {
		ev.Path = exe
		ev.Extra["exe"] = exe
	}
	// PATH/CWD join keys often appear on the same SYSCALL line as name=...
	if name := fields["name"]; name != "" {
		ev.Extra["path"] = name
		if ev.Path == "" || kind == KindOpenat {
			ev.Path = name
		}
	}
	if cwd := fields["cwd"]; cwd != "" {
		ev.Extra["cwd"] = cwd
		if kind == KindOpenat && ev.Path != "" && !strings.HasPrefix(ev.Path, "/") {
			ev.Path = strings.TrimRight(cwd, "/") + "/" + ev.Path
			ev.Extra["path"] = ev.Path
		}
	}
	if key := fields["key"]; key != "" {
		ev.Extra["key"] = key
	}
	// Audit prints syscall arguments as hex without the 0x prefix.
	// For socket() and splice() we capture them so downstream detectors
	// (e.g. CVE-2026-31431 / Copy Fail) can reason about the syscall
	// shape without needing kernel-side eBPF.
	if kind == KindSocket || kind == KindSplice {
		for _, k := range []string{"a0", "a1", "a2", "a3", "exit", "success"} {
			if v, ok := fields[k]; ok && v != "" {
				ev.Extra[k] = v
			}
		}
	}
	if kind == KindConnect {
		if addr := fields["addr"]; addr != "" {
			ev.Extra["addr"] = addr
			ev.RemoteIP = decodeAuditAddr(addr)
		}
	}
	return ev, true
}

// decodeAuditAddr best-effort decodes an audit hex IPv4 sockaddr dump.
func decodeAuditAddr(hexAddr string) string {
	// Common form for AF_INET: 0200PORTIPBYTES... — length varies.
	if len(hexAddr) < 16 {
		return ""
	}
	b := make([]byte, len(hexAddr)/2)
	for i := 0; i+1 < len(hexAddr); i += 2 {
		v, err := strconv.ParseUint(hexAddr[i:i+2], 16, 8)
		if err != nil {
			return ""
		}
		b[i/2] = byte(v)
	}
	if len(b) >= 8 && b[0] == 0x02 { // AF_INET
		return net.IP(b[4:8]).String()
	}
	return ""
}
