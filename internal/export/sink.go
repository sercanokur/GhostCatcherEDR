// Package export hosts the pluggable Sink interface used by Runner.emit
// to deliver events to SIEM/logging backends. Each concrete sink lives
// in its own sub-package. The shared error type lets the runner decide
// whether to spool or drop.
package export

import (
	"context"

	"ghostcatcher/internal/event"
)

// Sink is the common contract that runner.emit speaks. Every backend
// implements it so new destinations can be added without surgery to
// the runner.
type Sink interface {
	Name() string
	// Send is expected to be blocking but bounded: implementations that
	// can retry internally should do so before returning. The runner
	// spools on any error returned here.
	Send(ctx context.Context, e *event.Event, raw []byte) error
	Close() error
}
