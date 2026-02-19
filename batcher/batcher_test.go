package batcher_test

import (
	"context"
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
