// Package sensor provides a runtime-selected event source for exec,
// openat, connect, ptrace, init_module, and memfd_create system calls.
// The selection order is:
//
//  1. eBPF (built with -tags with_ebpf). Zero-copy, in-kernel filtering.
//  2. auditd (via /var/run/audispd_events or our own parser of
//     /var/log/audit/audit.log). Works on any Linux with auditd enabled.
//  3. /proc polling (always available, coarse-grained). Catches long-lived
//     new processes and listening sockets.
//
// All three backends emit the same Event struct so upstream correlation
// code does not need to know which one fired.
package sensor

import (
	"context"
	"time"
)

// Event is the canonical sensor signal.
type Event struct {
	Kind       Kind
	When       time.Time
	PID        int
	PPID       int
	UID        uint32
	Comm       string
	Argv       []string
	Path       string
	RemoteIP   string
	RemotePort int
	SyscallNR  int
	Extra      map[string]string
}

// Kind enumerates the interesting syscalls.
type Kind string

const (
	KindExec        Kind = "exec"
	KindOpenat      Kind = "openat"
	KindConnect     Kind = "connect"
	KindPtrace      Kind = "ptrace"
	KindInitModule  Kind = "init_module"
	KindMemfdCreate Kind = "memfd_create"
	KindListen      Kind = "listen"
	// KindSocket / KindSplice were added so the copy-fail (CVE-2026-31431)
	// detector can observe AF_ALG SOCK_SEQPACKET socket creation and the
	// follow-up splice() that drives the AEAD page-cache write primitive.
	KindSocket Kind = "socket"
	KindSplice Kind = "splice"
)

// Source is any backend that can stream sensor events into a channel
// until its context is cancelled.
type Source interface {
	Name() string
	Start(ctx context.Context, out chan<- Event) error
	Close() error
}

// Auto picks the best available Source at runtime. Callers must close
// the returned source to release kernel/program resources. Never returns
// a nil Source; the /proc fallback always succeeds.
func Auto(ctx context.Context) (Source, error) {
	if s, err := newEBPF(ctx); err == nil && s != nil {
		return s, nil
	}
	if s, err := newAuditd(ctx); err == nil && s != nil {
		return s, nil
	}
	return newProcPoll(ctx)
}
