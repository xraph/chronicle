// Package batcher provides batched event writing for Chronicle.
// Events are accumulated and flushed on size threshold, time interval, or shutdown.
package batcher

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/xraph/chronicle/audit"
)

// FlushFunc is called when a batch of events is ready to be persisted.
type FlushFunc func(ctx context.Context, events []*audit.Event) error

// Batcher accumulates events and flushes them in batches.
type Batcher struct {
	mu            sync.Mutex
	buffer        []*audit.Event
	batchSize     int
	flushInterval time.Duration
	flushFn       FlushFunc
	logger        *slog.Logger

	stopCh chan struct{}
	doneCh chan struct{}
}

// New creates a new Batcher.
func New(batchSize int, flushInterval time.Duration, flushFn FlushFunc, logger *slog.Logger) *Batcher {
	if logger == nil {
		logger = slog.Default()
	}
	return &Batcher{
		buffer:        make([]*audit.Event, 0, batchSize),
		batchSize:     batchSize,
		flushInterval: flushInterval,
		flushFn:       flushFn,
		logger:        logger,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
}

// Start begins the background flush ticker.
func (b *Batcher) Start() {
	go b.run()
}

// Add adds an event to the batch buffer. If the batch is full, it flushes immediately.
func (b *Batcher) Add(ctx context.Context, event *audit.Event) error {
	b.mu.Lock()
	b.buffer = append(b.buffer, event)
	if len(b.buffer) >= b.batchSize {
		batch := b.buffer
		b.buffer = make([]*audit.Event, 0, b.batchSize)
		b.mu.Unlock()
		return b.flush(ctx, batch)
	}
	b.mu.Unlock()
	return nil
}

// Stop signals the batcher to stop and flushes remaining events.
func (b *Batcher) Stop(ctx context.Context) error {
	close(b.stopCh)
	<-b.doneCh

	// Final flush of remaining events.
	b.mu.Lock()
	batch := b.buffer
	b.buffer = nil
	b.mu.Unlock()

	if len(batch) > 0 {
		return b.flush(ctx, batch)
	}
	return nil
}

func (b *Batcher) run() {
	defer close(b.doneCh)

	ticker := time.NewTicker(b.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			b.mu.Lock()
			if len(b.buffer) == 0 {
				b.mu.Unlock()
				continue
			}
			batch := b.buffer
			b.buffer = make([]*audit.Event, 0, b.batchSize)
			b.mu.Unlock()

			if err := b.flush(context.Background(), batch); err != nil {
				b.logger.Error("batcher interval flush error",
					slog.String("error", err.Error()),
				)
			}
		case <-b.stopCh:
			return
		}
	}
}

func (b *Batcher) flush(ctx context.Context, batch []*audit.Event) error {
	if len(batch) == 0 {
		return nil
	}
	return b.flushFn(ctx, batch)
}
