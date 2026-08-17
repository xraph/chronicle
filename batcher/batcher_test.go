package batcher_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/batcher"
	"github.com/xraph/chronicle/id"
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

func TestBatcherFlushesOnSize(t *testing.T) {
	var mu sync.Mutex
	var flushed []*audit.Event

	flushFn := func(_ context.Context, events []*audit.Event) error {
		mu.Lock()
		flushed = append(flushed, events...)
		mu.Unlock()
		return nil
	}

	b := batcher.New(3, time.Hour, flushFn, nil)
	b.Start()
	defer func() { _ = b.Stop(context.Background()) }()

	ctx := context.Background()

	// Add 3 events — should trigger a flush.
	for range 3 {
		err := b.Add(ctx, testEvent())
		if err != nil {
			t.Fatalf("Add: %v", err)
		}
	}

	mu.Lock()
	count := len(flushed)
	mu.Unlock()

	if count != 3 {
		t.Errorf("expected 3 flushed events, got %d", count)
	}
}

func TestBatcherFlushesOnInterval(t *testing.T) {
	var mu sync.Mutex
	var flushed []*audit.Event

	flushFn := func(_ context.Context, events []*audit.Event) error {
		mu.Lock()
		flushed = append(flushed, events...)
		mu.Unlock()
		return nil
	}

	b := batcher.New(100, 50*time.Millisecond, flushFn, nil)
	b.Start()
	defer func() { _ = b.Stop(context.Background()) }()

	// Add 1 event (below batch size).
	err := b.Add(context.Background(), testEvent())
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Wait for interval flush.
	time.Sleep(150 * time.Millisecond)

	mu.Lock()
	count := len(flushed)
	mu.Unlock()

	if count != 1 {
		t.Errorf("expected 1 flushed event after interval, got %d", count)
	}
}

func TestBatcherFlushesOnShutdown(t *testing.T) {
	var mu sync.Mutex
	var flushed []*audit.Event

	flushFn := func(_ context.Context, events []*audit.Event) error {
		mu.Lock()
		flushed = append(flushed, events...)
		mu.Unlock()
		return nil
	}

	b := batcher.New(100, time.Hour, flushFn, nil)
	b.Start()

	// Add 2 events (below batch size, long interval).
	ctx := context.Background()
	for range 2 {
		err := b.Add(ctx, testEvent())
		if err != nil {
			t.Fatalf("Add: %v", err)
		}
	}

	// Stop should flush remaining.
	err := b.Stop(ctx)
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}

	mu.Lock()
	count := len(flushed)
	mu.Unlock()

	if count != 2 {
		t.Errorf("expected 2 flushed events on shutdown, got %d", count)
	}
}

// TestStopIsIdempotent pins that a second Stop does not panic.
//
// Stop closed stopCh unconditionally, so a caller with both a deferred Stop and
// an explicit one on the shutdown path crashed the process on a closed channel.
func TestStopIsIdempotent(t *testing.T) {
	var flushed [][]*audit.Event
	var mu sync.Mutex

	b := batcher.New(10, time.Hour, func(_ context.Context, events []*audit.Event) error {
		mu.Lock()
		defer mu.Unlock()
		flushed = append(flushed, events)
		return nil
	}, nil)
	b.Start()

	ctx := context.Background()
	if err := b.Add(ctx, testEvent()); err != nil {
		t.Fatalf("Add: %v", err)
	}

	if err := b.Stop(ctx); err != nil {
		t.Fatalf("first Stop: %v", err)
	}

	// Must not panic, and must not double-flush.
	if err := b.Stop(ctx); err != nil {
		t.Fatalf("second Stop: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(flushed) != 1 {
		t.Fatalf("expected exactly 1 flush across two Stops, got %d", len(flushed))
	}
}

// TestStopRetainsEventsWhenFlushFails pins that a failed final flush does not
// discard the batch, so a caller can retry instead of silently losing audit
// events during shutdown.
func TestStopRetainsEventsWhenFlushFails(t *testing.T) {
	var attempts int
	var mu sync.Mutex

	b := batcher.New(10, time.Hour, func(_ context.Context, _ []*audit.Event) error {
		mu.Lock()
		defer mu.Unlock()
		attempts++
		if attempts == 1 {
			return errors.New("store unavailable")
		}
		return nil
	}, nil)
	b.Start()

	ctx := context.Background()
	if err := b.Add(ctx, testEvent()); err != nil {
		t.Fatalf("Add: %v", err)
	}

	if err := b.Stop(ctx); err == nil {
		t.Fatal("Stop should surface the flush failure")
	}

	if got := b.Pending(); got != 1 {
		t.Fatalf("Pending = %d, want 1; a failed flush must not drop the batch", got)
	}

	// Retrying must now succeed and drain.
	if err := b.Flush(ctx); err != nil {
		t.Fatalf("retry Flush: %v", err)
	}
	if got := b.Pending(); got != 0 {
		t.Fatalf("Pending = %d after a successful retry, want 0", got)
	}
}

// TestAddRetainsEventsWhenSizeFlushFails covers the same property on the
// size-triggered path.
func TestAddRetainsEventsWhenSizeFlushFails(t *testing.T) {
	b := batcher.New(2, time.Hour, func(_ context.Context, _ []*audit.Event) error {
		return errors.New("store unavailable")
	}, nil)

	ctx := context.Background()
	if err := b.Add(ctx, testEvent()); err != nil {
		t.Fatalf("Add 1: %v", err)
	}
	if err := b.Add(ctx, testEvent()); err == nil {
		t.Fatal("the size-triggered flush should surface its failure")
	}

	if got := b.Pending(); got != 2 {
		t.Fatalf("Pending = %d, want 2; a failed flush must not drop the batch", got)
	}
}
