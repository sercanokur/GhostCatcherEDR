package sensor

import (
	"context"
	"fmt"
	"strings"
)

// Open returns a Source for the requested backend.
//
//	auto / ""   — prefer eBPF, then auditd, then /proc poll (never nil)
//	ebpf        — fail closed if eBPF cannot start
//	auditd      — fail closed if audit.log is unavailable
//	proc-poll   — always available
func Open(ctx context.Context, backend string) (Source, error) {
	switch strings.ToLower(strings.TrimSpace(backend)) {
	case "", "auto":
		return Auto(ctx)
	case "ebpf":
		s, err := newEBPF(ctx)
		if err != nil {
			return nil, fmt.Errorf("sensor.backend=ebpf: %w", err)
		}
		return s, nil
	case "auditd", "audit":
		s, err := newAuditd(ctx)
		if err != nil {
			return nil, fmt.Errorf("sensor.backend=auditd: %w", err)
		}
		return s, nil
	case "proc-poll", "procpoll", "proc":
		return newProcPoll(ctx)
	default:
		return nil, fmt.Errorf("unknown sensor.backend %q (want auto|ebpf|auditd|proc-poll)", backend)
	}
}
