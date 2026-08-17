package sink

import (
	"context"
	"errors"
	"fmt"

	log "github.com/xraph/go-utils/log"

	"github.com/xraph/chronicle/audit"
)

// MultiSink fans out events to multiple sinks.
//
// A failing sink does not stop the others: every sink is always attempted. The
// combined failure is then returned, so a caller that depends on the write
// having landed can tell. Returning nil here made MultiSink unsafe as a
// retention archive target, because the enforcer checks the archive write's
// error before purging and would delete events that were never archived.
type MultiSink struct {
	sinks  []Sink
	logger log.Logger
}

// NewMultiSink creates a MultiSink that fans out to the given sinks.
func NewMultiSink(logger log.Logger, sinks ...Sink) *MultiSink {
	if logger == nil {
		logger = log.NewNoopLogger()
	}
	return &MultiSink{
		sinks:  sinks,
		logger: logger,
	}
}

func (m *MultiSink) Name() string { return "multi" }

// Write sends events to every sink and returns the combined failure, if any.
func (m *MultiSink) Write(ctx context.Context, events []*audit.Event) error {
	return m.fanOut("write", func(s Sink) error { return s.Write(ctx, events) })
}

// Flush flushes every sink and returns the combined failure, if any.
func (m *MultiSink) Flush(ctx context.Context) error {
	return m.fanOut("flush", func(s Sink) error { return s.Flush(ctx) })
}

// Close closes every sink and returns the combined failure, if any.
func (m *MultiSink) Close() error {
	return m.fanOut("close", func(s Sink) error { return s.Close() })
}

// fanOut applies op to every sink, logging and collecting failures as it goes.
// Every sink is attempted even after one fails.
func (m *MultiSink) fanOut(opName string, op func(Sink) error) error {
	var errs []error
	for _, s := range m.sinks {
		if err := op(s); err != nil {
			m.logger.Error("sink "+opName+" error",
				log.String("sink", s.Name()),
				log.String("error", err.Error()),
			)
			errs = append(errs, fmt.Errorf("sink %s: %s: %w", s.Name(), opName, err))
		}
	}
	return errors.Join(errs...)
}

// Add appends a sink to the multi-sink fan-out.
func (m *MultiSink) Add(s Sink) {
	m.sinks = append(m.sinks, s)
}

// Sinks returns the list of registered sinks.
func (m *MultiSink) Sinks() []Sink {
	return m.sinks
}
