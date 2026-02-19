package sink

import (
	"context"
	"log/slog"

	"github.com/xraph/chronicle/audit"
)

// MultiSink fans out events to multiple sinks.
// Individual sink errors are logged but do not stop other sinks.
type MultiSink struct {
	sinks  []Sink
	logger *slog.Logger
}

// NewMultiSink creates a MultiSink that fans out to the given sinks.
func NewMultiSink(logger *slog.Logger, sinks ...Sink) *MultiSink {
	if logger == nil {
		logger = slog.Default()
	}
	return &MultiSink{
		sinks:  sinks,
		logger: logger,
	}
}

func (m *MultiSink) Name() string { return "multi" }

func (m *MultiSink) Write(ctx context.Context, events []*audit.Event) error {
	for _, s := range m.sinks {
		if err := s.Write(ctx, events); err != nil {
			m.logger.Error("sink write error",
				slog.String("sink", s.Name()),
				slog.String("error", err.Error()),
			)
		}
	}
	return nil
}

func (m *MultiSink) Flush(ctx context.Context) error {
	for _, s := range m.sinks {
		if err := s.Flush(ctx); err != nil {
			m.logger.Error("sink flush error",
				slog.String("sink", s.Name()),
				slog.String("error", err.Error()),
			)
		}
	}
	return nil
}

func (m *MultiSink) Close() error {
	for _, s := range m.sinks {
		if err := s.Close(); err != nil {
			m.logger.Error("sink close error",
				slog.String("sink", s.Name()),
				slog.String("error", err.Error()),
			)
		}
	}
	return nil
}

// Add appends a sink to the multi-sink fan-out.
func (m *MultiSink) Add(s Sink) {
	m.sinks = append(m.sinks, s)
}

// Sinks returns the list of registered sinks.
func (m *MultiSink) Sinks() []Sink {
	return m.sinks
}
