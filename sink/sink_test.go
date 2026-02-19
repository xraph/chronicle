package sink_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/sink"
)

func testEvent() *audit.Event {
	return &audit.Event{
		ID:        id.NewAuditID(),
		Timestamp: time.Now().UTC(),
		Action:    "create",
		Resource:  "user",
		Category:  "auth",
		Outcome:   audit.OutcomeSuccess,
		Severity:  audit.SeverityInfo,
	}
}

func TestStdoutSink(t *testing.T) {
	var buf bytes.Buffer
	s := sink.NewStdoutSink(&buf)

	if s.Name() != "stdout" {
		t.Errorf("Name = %q, want %q", s.Name(), "stdout")
	}

	events := []*audit.Event{testEvent(), testEvent()}
	err := s.Write(context.Background(), events)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Should have written 2 JSON lines.
	decoder := json.NewDecoder(&buf)
	count := 0
	for decoder.More() {
		var e audit.Event
		if err := decoder.Decode(&e); err != nil {
			t.Fatalf("Decode: %v", err)
		}
		count++
	}
	if count != 2 {
		t.Errorf("got %d events, want 2", count)
	}
}

func TestFileSink(t *testing.T) {
	dir := t.TempDir()
	s := sink.NewFileSink(dir, "audit")
	defer s.Close()

	if s.Name() != "file" {
		t.Errorf("Name = %q, want %q", s.Name(), "file")
	}

	events := []*audit.Event{testEvent(), testEvent(), testEvent()}
	err := s.Write(context.Background(), events)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	err = s.Flush(context.Background())
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// Check that a .jsonl file was created.
	matches, err := filepath.Glob(filepath.Join(dir, "audit-*.jsonl"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 file, got %d", len(matches))
	}

	// Check file contents.
	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 3 {
		t.Errorf("got %d lines, want 3", len(lines))
	}
}

func TestFileSinkRotation(t *testing.T) {
	dir := t.TempDir()
	// Very small max size to trigger rotation.
	s := sink.NewFileSink(dir, "audit", sink.WithMaxSize(100))
	defer s.Close()

	// Write enough events to trigger at least one rotation.
	for range 20 {
		err := s.Write(context.Background(), []*audit.Event{testEvent()})
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	matches, err := filepath.Glob(filepath.Join(dir, "audit-*.jsonl"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(matches) < 2 {
		t.Errorf("expected multiple files from rotation, got %d", len(matches))
	}
}

// errSink is a test sink that always returns an error.
type errSink struct {
	name string
}

func (e *errSink) Name() string                                    { return e.name }
func (e *errSink) Write(_ context.Context, _ []*audit.Event) error { return errors.New("sink error") }
func (e *errSink) Flush(_ context.Context) error                   { return errors.New("flush error") }
func (e *errSink) Close() error                                    { return errors.New("close error") }

func TestMultiSinkFanOut(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	s1 := sink.NewStdoutSink(&buf1)
	s2 := sink.NewStdoutSink(&buf2)
	multi := sink.NewMultiSink(slog.Default(), s1, s2)

	if multi.Name() != "multi" {
		t.Errorf("Name = %q, want %q", multi.Name(), "multi")
	}

	events := []*audit.Event{testEvent()}
	err := multi.Write(context.Background(), events)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	if buf1.Len() == 0 {
		t.Error("sink1 should have received events")
	}
	if buf2.Len() == 0 {
		t.Error("sink2 should have received events")
	}
}

func TestMultiSinkSurvivesErrors(t *testing.T) {
	var buf bytes.Buffer
	good := sink.NewStdoutSink(&buf)
	bad := &errSink{name: "bad"}
	multi := sink.NewMultiSink(slog.Default(), bad, good)

	events := []*audit.Event{testEvent()}
	err := multi.Write(context.Background(), events)
	if err != nil {
		t.Fatalf("MultiSink.Write should not return error, got: %v", err)
	}

	// Good sink should still have received the event.
	if buf.Len() == 0 {
		t.Error("good sink should have received events despite bad sink error")
	}
}

func TestMultiSinkAdd(t *testing.T) {
	multi := sink.NewMultiSink(nil)
	if len(multi.Sinks()) != 0 {
		t.Fatalf("expected 0 sinks, got %d", len(multi.Sinks()))
	}

	multi.Add(sink.Stdout())
	if len(multi.Sinks()) != 1 {
		t.Fatalf("expected 1 sink, got %d", len(multi.Sinks()))
	}
}
