//go:build !with_ebpf

package sensor

import (
	"context"
	"errors"
)

// newEBPF returns an error on non-ebpf builds so Auto falls through to the
// next backend. The stub deliberately does nothing at import time.
func newEBPF(_ context.Context) (Source, error) {
	return nil, errors.New("ebpf: not built with with_ebpf tag")
}
