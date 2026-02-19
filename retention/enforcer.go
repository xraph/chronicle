package retention

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/sink"
)

// EnforceResult contains the results of a retention enforcement run.
type EnforceResult struct {
	Archived int64 `json:"archived"`
	Purged   int64 `json:"purged"`
	Retained int64 `json:"retained"`
}

// Enforcer runs retention policies: finds old events, optionally archives them, then purges.
type Enforcer struct {
	store       Store
	archiveSink sink.Sink
	logger      *slog.Logger
}

// NewEnforcer creates a retention enforcer.
// archiveSink may be nil if no archiving is needed.
func NewEnforcer(store Store, archiveSink sink.Sink, logger *slog.Logger) *Enforcer {
	if logger == nil {
		logger = slog.Default()
	}
	return &Enforcer{
		store:       store,
		archiveSink: archiveSink,
		logger:      logger,
	}
}

// Enforce runs all retention policies once.
// For each policy, it finds events older than the retention duration,
// optionally archives them to the archive sink, then purges them from the store.
func (e *Enforcer) Enforce(ctx context.Context) (*EnforceResult, error) {
	policies, err := e.store.ListPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("retention: list policies: %w", err)
	}

	result := &EnforceResult{}

	for _, policy := range policies {
		policyResult, err := e.enforcePolicy(ctx, policy)
		if err != nil {
			e.logger.Error("retention: enforce policy failed",
				"policy_id", policy.ID,
				"category", policy.Category,
				"error", err,
			)
			continue
		}
		result.Archived += policyResult.Archived
		result.Purged += policyResult.Purged
		result.Retained += policyResult.Retained
	}

	return result, nil
}

func (e *Enforcer) enforcePolicy(ctx context.Context, policy *Policy) (*EnforceResult, error) {
	cutoff := time.Now().Add(-policy.Duration)
	result := &EnforceResult{}

	events, err := e.store.EventsOlderThan(ctx, policy.Category, cutoff)
	if err != nil {
		return nil, fmt.Errorf("events older than %v: %w", policy.Duration, err)
	}

	if len(events) == 0 {
		return result, nil
	}

	// Archive if policy requires it and we have a sink.
	if policy.Archive && e.archiveSink != nil {
		if writeErr := e.archiveSink.Write(ctx, events); writeErr != nil {
			return nil, fmt.Errorf("archive write: %w", writeErr)
		}

		if flushErr := e.archiveSink.Flush(ctx); flushErr != nil {
			return nil, fmt.Errorf("archive flush: %w", flushErr)
		}

		// Determine time range.
		minTS, maxTS := events[0].Timestamp, events[0].Timestamp
		for _, ev := range events[1:] {
			if ev.Timestamp.Before(minTS) {
				minTS = ev.Timestamp
			}
			if ev.Timestamp.After(maxTS) {
				maxTS = ev.Timestamp
			}
		}

		archive := &Archive{
			ID:            id.NewArchiveID(),
			PolicyID:      policy.ID,
			Category:      policy.Category,
			EventCount:    int64(len(events)),
			FromTimestamp: minTS,
			ToTimestamp:   maxTS,
			SinkName:      e.archiveSink.Name(),
		}
		archive.CreatedAt = time.Now()

		if recordErr := e.store.RecordArchive(ctx, archive); recordErr != nil {
			return nil, fmt.Errorf("record archive: %w", recordErr)
		}

		result.Archived = int64(len(events))
	}

	// Purge the events.
	eventIDs := make([]id.ID, len(events))
	for i, ev := range events {
		eventIDs[i] = ev.ID
	}

	purged, purgeErr := e.store.PurgeEvents(ctx, eventIDs)
	if purgeErr != nil {
		return nil, fmt.Errorf("purge events: %w", purgeErr)
	}

	result.Purged = purged

	e.logger.Info("retention: policy enforced",
		"policy_id", policy.ID,
		"category", policy.Category,
		"archived", result.Archived,
		"purged", result.Purged,
	)

	return result, nil
}
