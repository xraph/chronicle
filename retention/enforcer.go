package retention

import (
	"context"
	"fmt"
	"time"

	log "github.com/xraph/go-utils/log"

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
	logger      log.Logger
}

// NewEnforcer creates a retention enforcer.
// archiveSink may be nil if no archiving is needed.
func NewEnforcer(store Store, archiveSink sink.Sink, logger log.Logger) *Enforcer {
	if logger == nil {
		logger = log.NewNoopLogger()
	}
	return &Enforcer{
		store:       store,
		archiveSink: archiveSink,
		logger:      logger,
	}
}

// Enforce runs every retention policy once, each against its own scope.
//
// This is the entry point for the background scheduler, which legitimately
// covers all apps and tenants. Each policy still only purges the events its own
// (AppID, TenantID) owns. Request handlers must call EnforceScope instead, so a
// caller cannot trigger another tenant's retention.
func (e *Enforcer) Enforce(ctx context.Context) (*EnforceResult, error) {
	return e.enforce(ctx, ListPoliciesOpts{Limit: -1})
}

// EnforceScope runs only the policies owned by the given scope.
func (e *Enforcer) EnforceScope(ctx context.Context, s Scope) (*EnforceResult, error) {
	return e.enforce(ctx, ListPoliciesOpts{Scope: s, Limit: -1})
}

func (e *Enforcer) enforce(ctx context.Context, opts ListPoliciesOpts) (*EnforceResult, error) {
	policies, err := e.store.ListPolicies(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("retention: list policies: %w", err)
	}

	result := &EnforceResult{}
	var firstErr error

	for _, policy := range policies {
		policyResult, err := e.enforcePolicy(ctx, policy)
		if err != nil {
			e.logger.Error("retention: enforce policy failed",
				log.String("policy_id", policy.ID.String()),
				log.String("category", policy.Category),
				log.String("app_id", policy.AppID),
				log.String("tenant_id", policy.TenantID),
				log.String("error", err.Error()),
			)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		result.Archived += policyResult.Archived
		result.Purged += policyResult.Purged
		result.Retained += policyResult.Retained
	}

	// Surface a failure rather than reporting a clean run. A caller that sees
	// only counts cannot tell that archiving broke and nothing was purged.
	if firstErr != nil {
		return result, fmt.Errorf("retention: %w", firstErr)
	}

	return result, nil
}

func (e *Enforcer) enforcePolicy(ctx context.Context, policy *Policy) (*EnforceResult, error) {
	cutoff := time.Now().Add(-policy.Duration)
	result := &EnforceResult{}

	// Security-critical: the query carries the policy's own scope, so a policy
	// can only ever purge the events its app and tenant own.
	events, err := e.store.EventsOlderThan(ctx, PurgeQuery{
		Scope:    policy.Scope(),
		Category: policy.Category,
		Before:   cutoff,
	})
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
			AppID:         policy.AppID,
			TenantID:      policy.TenantID,
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
		log.String("policy_id", policy.ID.String()),
		log.String("category", policy.Category),
		log.Int64("archived", result.Archived),
		log.Int64("purged", result.Purged),
	)

	return result, nil
}
