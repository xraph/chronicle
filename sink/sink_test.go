package sink_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/xraph/go-utils/log"

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
	multi := sink.NewMultiSink(log.NewNoopLogger(), s1, s2)

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

// TestMultiSinkDeliversToEverySinkAndReportsFailures pins both halves of the
// fan-out contract: one sink failing must not stop the others, and the failure
// must still be returned.
//
// Returning nil made MultiSink unusable as a retention archive target: the
// enforcer checks the archive write's error before purging, so a swallowed error
// meant events were deleted after never being archived.
func TestMultiSinkDeliversToEverySinkAndReportsFailures(t *testing.T) {
	var buf bytes.Buffer
	good := sink.NewStdoutSink(&buf)
	bad := &errSink{name: "bad"}
	multi := sink.NewMultiSink(log.NewNoopLogger(), bad, good)

	events := []*audit.Event{testEvent()}
	err := multi.Write(context.Background(), events)
	if err == nil {
		t.Fatal("MultiSink.Write must report the failing sink, otherwise callers purge unarchived data")
	}
	if !strings.Contains(err.Error(), "bad") {
		t.Errorf("error should name the failing sink, got: %v", err)
	}

	// The healthy sink must still have received the event.
	if buf.Len() == 0 {
		t.Error("good sink should have received events despite the bad sink error")
	}
}

func TestMultiSinkReportsFlushAndCloseFailures(t *testing.T) {
	bad := &errSink{name: "bad"}
	multi := sink.NewMultiSink(log.NewNoopLogger(), bad)

	if err := multi.Flush(context.Background()); err == nil {
		t.Error("Flush must report the failing sink")
	}
	if err := multi.Close(); err == nil {
		t.Error("Close must report the failing sink")
	}
}

func TestMultiSinkAggregatesEveryFailure(t *testing.T) {
	multi := sink.NewMultiSink(log.NewNoopLogger(),
		&errSink{name: "first"}, &errSink{name: "second"})

	err := multi.Write(context.Background(), []*audit.Event{testEvent()})
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, name := range []string{"first", "second"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error should mention %q, got: %v", name, err)
		}
	}
}

func TestMultiSinkSucceedsWhenAllSinksSucceed(t *testing.T) {
	var buf bytes.Buffer
	multi := sink.NewMultiSink(log.NewNoopLogger(), sink.NewStdoutSink(&buf))

	if err := multi.Write(context.Background(), []*audit.Event{testEvent()}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := multi.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
}

// ──────────────────────────────────────────────────
// S3 sink
// ──────────────────────────────────────────────────

// fakeS3 records every PutObject call.
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	puts    int
	failOn  string
}

func newFakeS3() *fakeS3 {
	return &fakeS3{objects: make(map[string][]byte)}
}

func (f *fakeS3) PutObject(_ context.Context, _, key string, body io.Reader) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.failOn != "" && strings.Contains(key, f.failOn) {
		return errors.New("put failed")
	}

	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	f.objects[key] = data
	f.puts++
	return nil
}

func (f *fakeS3) keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	keys := make([]string, 0, len(f.objects))
	for k := range f.objects {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func s3TestEvent(category string, ts time.Time) *audit.Event {
	e := testEvent()
	e.Category = category
	e.Timestamp = ts
	return e
}

// TestS3SinkDoesNotOverwriteEarlierFlushes pins the key-collision fix. Two
// flushes of different events landing in the same category and day used to
// resolve to one key, so the second PutObject replaced the first archive. The
// retention enforcer then purged the source rows, losing the first batch from
// both S3 and the database.
func TestS3SinkDoesNotOverwriteEarlierFlushes(t *testing.T) {
	fake := newFakeS3()
	s := sink.NewS3Sink(fake, "bucket", "archives")
	ctx := context.Background()
	day := time.Date(2024, 3, 5, 12, 0, 0, 0, time.UTC)

	if err := s.Write(ctx, []*audit.Event{s3TestEvent("auth", day)}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("Flush 1: %v", err)
	}

	if err := s.Write(ctx, []*audit.Event{s3TestEvent("auth", day.Add(time.Hour))}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("Flush 2: %v", err)
	}

	keys := fake.keys()
	if len(keys) != 2 {
		t.Fatalf("expected 2 distinct objects, got %d: %v", len(keys), keys)
	}
}

// TestS3SinkKeyIsIdempotentForTheSameBatch means a retried flush of identical
// content overwrites itself rather than piling up duplicates.
func TestS3SinkKeyIsIdempotentForTheSameBatch(t *testing.T) {
	fake := newFakeS3()
	ctx := context.Background()
	day := time.Date(2024, 3, 5, 12, 0, 0, 0, time.UTC)
	event := s3TestEvent("auth", day)

	for range 2 {
		s := sink.NewS3Sink(fake, "bucket", "archives")
		if err := s.Write(ctx, []*audit.Event{event}); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := s.Flush(ctx); err != nil {
			t.Fatalf("Flush: %v", err)
		}
	}

	if keys := fake.keys(); len(keys) != 1 {
		t.Fatalf("identical batches should share one key, got %d: %v", len(keys), keys)
	}
}

func TestS3SinkPartitionsByCategoryAndDay(t *testing.T) {
	fake := newFakeS3()
	s := sink.NewS3Sink(fake, "bucket", "archives")
	ctx := context.Background()
	day := time.Date(2024, 3, 5, 12, 0, 0, 0, time.UTC)

	events := []*audit.Event{
		s3TestEvent("auth", day),
		s3TestEvent("data", day),
		s3TestEvent("auth", day.AddDate(0, 0, 1)),
	}
	if err := s.Write(ctx, events); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	keys := fake.keys()
	if len(keys) != 3 {
		t.Fatalf("expected 3 partitions, got %d: %v", len(keys), keys)
	}
	for _, k := range keys {
		if !strings.HasPrefix(k, "archives/") {
			t.Errorf("key %q should start with the prefix", k)
		}
		if !strings.HasSuffix(k, ".jsonl.gz") {
			t.Errorf("key %q should end with .jsonl.gz", k)
		}
	}
}

// TestS3SinkEscapesCategoryInKey stops a category from steering the object path.
//
// The property that matters is structural: the category must collapse to exactly
// one key segment, and no segment may be a traversal. Odd characters inside a
// segment are harmless.
func TestS3SinkEscapesCategoryInKey(t *testing.T) {
	ctx := context.Background()
	day := time.Date(2024, 3, 5, 12, 0, 0, 0, time.UTC)

	// prefix/category/YYYY/MM/DD/filename
	const wantSegments = 6

	for _, category := range []string{
		"../../etc/passwd",
		"..",
		".",
		"a/b/c",
		"",
		"auth\x00evil",
	} {
		t.Run(category, func(t *testing.T) {
			fake := newFakeS3()
			s := sink.NewS3Sink(fake, "bucket", "archives")

			if err := s.Write(ctx, []*audit.Event{s3TestEvent(category, day)}); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if err := s.Flush(ctx); err != nil {
				t.Fatalf("Flush: %v", err)
			}

			keys := fake.keys()
			if len(keys) != 1 {
				t.Fatalf("expected 1 object, got %v", keys)
			}

			segments := strings.Split(keys[0], "/")
			if len(segments) != wantSegments {
				t.Fatalf("category %q produced %d segments, want %d: %q",
					category, len(segments), wantSegments, keys[0])
			}
			for _, seg := range segments {
				if seg == "." || seg == ".." || seg == "" {
					t.Fatalf("key %q contains a traversal or empty segment", keys[0])
				}
			}
		})
	}
}

// TestS3SinkFlushReportsFailure means the enforcer will not purge on a failed
// upload.
func TestS3SinkFlushReportsFailure(t *testing.T) {
	fake := newFakeS3()
	fake.failOn = "auth"
	s := sink.NewS3Sink(fake, "bucket", "archives")
	ctx := context.Background()

	if err := s.Write(ctx, []*audit.Event{s3TestEvent("auth", time.Now().UTC())}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := s.Flush(ctx); err == nil {
		t.Fatal("Flush must report the upload failure")
	}
}

// TestS3SinkRetainsBufferOnFailure means a failed flush can be retried instead of
// dropping the batch.
func TestS3SinkRetainsBufferOnFailure(t *testing.T) {
	fake := newFakeS3()
	fake.failOn = "auth"
	s := sink.NewS3Sink(fake, "bucket", "archives")
	ctx := context.Background()

	if err := s.Write(ctx, []*audit.Event{s3TestEvent("auth", time.Now().UTC())}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := s.Flush(ctx); err == nil {
		t.Fatal("expected the first flush to fail")
	}

	// The target recovers; retrying must still have the events.
	fake.failOn = ""
	if err := s.Flush(ctx); err != nil {
		t.Fatalf("retry Flush: %v", err)
	}
	if len(fake.keys()) != 1 {
		t.Fatalf("expected the retried batch to be uploaded, got %v", fake.keys())
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
