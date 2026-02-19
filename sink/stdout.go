package sink

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"sync"

	"github.com/xraph/chronicle/audit"
)

// StdoutSink writes events as JSON to an io.Writer (defaults to os.Stdout).
type StdoutSink struct {
	mu     sync.Mutex
	writer io.Writer
	enc    *json.Encoder
}

// Stdout creates a new StdoutSink writing to os.Stdout.
func Stdout() *StdoutSink {
	return NewStdoutSink(os.Stdout)
}

// NewStdoutSink creates a StdoutSink writing to the given writer.
func NewStdoutSink(w io.Writer) *StdoutSink {
	return &StdoutSink{
		writer: w,
		enc:    json.NewEncoder(w),
	}
}

func (s *StdoutSink) Name() string { return "stdout" }

func (s *StdoutSink) Write(_ context.Context, events []*audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, e := range events {
		if err := s.enc.Encode(e); err != nil {
			return err
		}
	}
	return nil
}

func (s *StdoutSink) Flush(_ context.Context) error { return nil }
func (s *StdoutSink) Close() error                  { return nil }
