// Package sink defines the Sink interface and built-in sink implementations.
// Sinks are fire-and-forget output targets — separate from the structured store.
// Errors on sinks are logged, never fatal.
package sink

import (
	"context"

	"github.com/xraph/chronicle/audit"
)

// Sink writes events to an output destination.
// Unlike the store, sinks are fire-and-forget — errors are logged, not fatal.
type Sink interface {
	Name() string
	Write(ctx context.Context, events []*audit.Event) error
	Flush(ctx context.Context) error
	Close() error
}
