//go:build with_ebpf && linux

// This file is intentionally a thin wrapper: we load a set of tracepoint
// programs (exec, openat, connect, ptrace, init_module, memfd_create)
// and fan their ring buffer into the sensor.Event channel. The CO-RE
// object must be built from bpf/sensor.c using clang; if it is missing
// at runtime we fall through to the next backend.
//
// Because the eBPF object file is not checked into the repository in
// this change (building it requires clang/libbpf on the target kernel),
// this implementation is conservative: it only activates when the
// object is found next to the agent binary. Otherwise Auto() falls
// through to auditd and /proc polling.
package sensor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type ebpfSource struct {
	coll *ebpf.Collection
	rb   *ringbuf.Reader
	lnks []link.Link
}

func (e *ebpfSource) Name() string { return "ebpf" }

func newEBPF(ctx context.Context) (Source, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit: %w", err)
	}
	obj, err := findObj()
	if err != nil {
		return nil, err
	}
	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new coll: %w", err)
	}
	rbMap, ok := coll.Maps["events"]
	if !ok {
		coll.Close()
		return nil, errors.New("ebpf: events map missing")
	}
	rb, err := ringbuf.NewReader(rbMap)
	if err != nil {
		coll.Close()
		return nil, err
	}
	lnks := []link.Link{}
	for name, prog := range coll.Programs {
		l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: name, Program: prog})
		if err != nil {
			// Ignore individual attach failures; we want partial coverage
			// rather than losing everything.
			continue
		}
		lnks = append(lnks, l)
	}
	if len(lnks) == 0 {
		rb.Close()
		coll.Close()
		return nil, errors.New("ebpf: no tracepoints attached")
	}
	return &ebpfSource{coll: coll, rb: rb, lnks: lnks}, nil
}

func (e *ebpfSource) Start(ctx context.Context, out chan<- Event) error {
	go func() {
		<-ctx.Done()
		_ = e.rb.Close()
	}()
	for {
		rec, err := e.rb.Read()
		if err != nil {
			return nil
		}
		// The ringbuf payload layout is owned by bpf/sensor.c. Until that
		// object is shipped we just pass a minimal placeholder event with
		// the raw bytes in Extra so the UX remains visible.
		out <- Event{Kind: KindExec, Extra: map[string]string{"raw_len": fmt.Sprintf("%d", len(rec.RawSample))}}
	}
}

func (e *ebpfSource) Close() error {
	for _, l := range e.lnks {
		_ = l.Close()
	}
	if e.rb != nil {
		_ = e.rb.Close()
	}
	if e.coll != nil {
		e.coll.Close()
	}
	return nil
}

func findObj() (string, error) {
	candidates := []string{
		"/etc/ghostcatcher/ebpf/sensor.bpf.o",
		"/usr/lib/ghostcatcher/sensor.bpf.o",
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "sensor.bpf.o"))
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", errors.New("ebpf: sensor.bpf.o not found")
}
