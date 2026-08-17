// Package batcher provides batched event writing for Chronicle.
// Events are accumulated and flushed on size threshold, time interval, or shutdown.
package batcher

import (
	"context"
	"sync"

	"time"

	log "github.com/xraph/go-utils/log"

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
	logger        log.Logger

	stopCh   chan struct{}
	doneCh   chan struct{}
	stopOnce sync.Once
}

// New creates a new Batcher.
func New(batchSize int, flushInterval time.Duration, flushFn FlushFunc, logger log.Logger) *Batcher {
	if logger == nil {
		logger = log.NewNoopLogger()
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

// Add adds an event to the batch buffer. If the batch is full, it flushes
// immediately.
//
// A failed flush leaves the events buffered so a later flush can retry, rather
// than dropping audit records because the store was briefly unavailable.
func (b *Batcher) Add(ctx context.Context, event *audit.Event) error {
	b.mu.Lock()
	b.buffer = append(b.buffer, event)
	full := len(b.buffer) >= b.batchSize
	b.mu.Unlock()

	if !full {
		return nil
	}
	return b.Flush(ctx)
}

// Flush writes any buffered events. The buffer is only cleared once flushFn
// succeeds, so a failure can be retried without losing the batch.
func (b *Batcher) Flush(ctx context.Context) error {
	b.mu.Lock()
	batch := b.buffer
	b.mu.Unlock()

	if len(batch) == 0 {
		return nil
	}

	if err := b.flushFn(ctx, batch); err != nil {
		return err
	}

	// Drop only what was written; Add may have appended more meanwhile.
	b.mu.Lock()
	b.buffer = b.buffer[len(batch):]
	b.mu.Unlock()

	return nil
}

// Pending reports how many events are buffered.
func (b *Batcher) Pending() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.buffer)
}

// Stop signals the batcher to stop and flushes remaining events.
//
// Safe to call more than once: a caller that both defers Stop and calls it on
// the shutdown path used to panic here, because stopCh was closed twice.
func (b *Batcher) Stop(ctx context.Context) error {
	b.stopOnce.Do(func() {
		close(b.stopCh)
		<-b.doneCh
	})

	return b.Flush(ctx)
}

func (b *Batcher) run() {
	defer close(b.doneCh)

	ticker := time.NewTicker(b.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := b.Flush(context.Background()); err != nil {
				b.logger.Error("batcher interval flush error",
					log.String("error", err.Error()),
				)
			}
		case <-b.stopCh:
			return
		}
	}
}
