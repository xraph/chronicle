package retention

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	log "github.com/xraph/go-utils/log"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/sink"
)

// EnforceResult contains the results of a retention enforcement run.
type EnforceResult struct {
	Archived int64 `json:"archived"`
	Purged   int64 `json:"purged"`
	Retained int64 `json:"retained"`
}

// ErrNoChainRecorder is returned when an Enforcer would purge events with no
// ChainRecorder to record the purge in the hash chain.
//
// Purging without a record leaves holes that verification cannot tell apart
// from an attacker deleting events, so every stream a policy touches reports
// as broken from then on, and a real deletion hides among them. An Enforcer
// refuses to do that unless it was built with WithUnrecordedPurge.
var ErrNoChainRecorder = errors.New(
	"retention: no chain recorder configured; purging would leave gaps verification " +
		"reports as deletions (use WithChainRecorder, or WithUnrecordedPurge to accept that)",
)

// ErrPolicyWithoutApp is returned when an Enforcer is handed a policy with no
// AppID. It purges nothing for that policy.
//
// Every list filter reads an empty AppID as every app, so a policy that
// reaches the enforcer without one is a row nothing should have produced.
// Guessing what it was meant to cover is not worth an unrecoverable purge.
var ErrPolicyWithoutApp = errors.New("retention: policy has no app ID; refusing to enforce it")

// ChainRecorder records a retention purge in the hash chain before the events
// are deleted. *chronicle.Chronicle implements it.
type ChainRecorder interface {
	// RecordRetention appends a record listing the given events to each of
	// their streams and returns the IDs it recorded. Only those may be
	// purged. It may return recorded IDs alongside an error, and purging
	// those is still correct.
	RecordRetention(ctx context.Context, ref audit.RetentionRef, events []*audit.Event) ([]id.ID, error)
}

// Enforcer runs retention policies: finds old events, optionally archives them, then purges.
type Enforcer struct {
	store       Store
	archiveSink sink.Sink
	logger      log.Logger

	recorder   ChainRecorder
	unrecorded bool
}

// EnforcerOption configures an Enforcer.
type EnforcerOption func(*Enforcer)

// WithChainRecorder records every purge in the hash chain first, so
// verification reports the removed sequences as retained rather than missing.
// Pass the *chronicle.Chronicle that writes the streams being purged.
func WithChainRecorder(r ChainRecorder) EnforcerOption {
	return func(e *Enforcer) { e.recorder = r }
}

// WithUnrecordedPurge lets an Enforcer with no ChainRecorder purge anyway.
//
// Every purge then leaves gaps that verification reports exactly as it would
// an attacker's deletion. Use it only for a store whose events are not
// hash-chained, or where the chain is knowingly not verified.
func WithUnrecordedPurge() EnforcerOption {
	return func(e *Enforcer) { e.unrecorded = true }
}

// NewEnforcer creates a retention enforcer.
// archiveSink may be nil if no archiving is needed.
//
// Without WithChainRecorder or WithUnrecordedPurge, enforcing a policy that
// selects any events fails with ErrNoChainRecorder and purges nothing.
func NewEnforcer(store Store, archiveSink sink.Sink, logger log.Logger, opts ...EnforcerOption) *Enforcer {
	if logger == nil {
		logger = log.NewNoopLogger()
	}
	e := &Enforcer{
		store:       store,
		archiveSink: archiveSink,
		logger:      logger,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Enforce runs every retention policy once, each against its own scope.
//
// This is the entry point for the background scheduler, which legitimately
// covers all apps and tenants. Each policy still only purges the events its own
// (AppID, TenantID) owns. Request handlers must call EnforceScope instead, so a
// caller cannot trigger another tenant's retention.
func (e *Enforcer) Enforce(ctx context.Context) (*EnforceResult, error) {
	return e.enforce(ctx, ListPoliciesOpts{Limit: -1}, nil)
}

// EnforceScope runs only the policies owned by the given scope.
//
// A policy the store returns from outside s is skipped, so a store whose
// ListPolicies ignores the scope still cannot make one caller purge
// another's events.
func (e *Enforcer) EnforceScope(ctx context.Context, s Scope) (*EnforceResult, error) {
	return e.EnforceScopeFunc(ctx, s, nil)
}

// EnforceScopeFunc is EnforceScope with the caller's own ownership check:
// only the policies keep reports true for are run. It is applied before
// anything is read or purged, on top of the scope check EnforceScope already
// does. A nil keep runs every policy in s.
//
// Use it when the caller's idea of what a viewer owns is stricter than the
// listing scope, so the policies it enforces are the same ones it shows.
func (e *Enforcer) EnforceScopeFunc(
	ctx context.Context, s Scope, keep func(*Policy) bool,
) (*EnforceResult, error) {
	return e.enforce(ctx, ListPoliciesOpts{Scope: s, Limit: -1}, func(p *Policy) bool {
		return inListScope(p, s) && (keep == nil || keep(p))
	})
}

// inListScope reports whether p falls inside s the way ListPolicies reads s:
// an empty field matches any value, a set one must match exactly.
func inListScope(p *Policy, s Scope) bool {
	return (s.AppID == "" || p.AppID == s.AppID) &&
		(s.TenantID == "" || p.TenantID == s.TenantID)
}

// enforce runs the listed policies that keep reports true for. A nil keep
// runs all of them.
func (e *Enforcer) enforce(
	ctx context.Context, opts ListPoliciesOpts, keep func(*Policy) bool,
) (*EnforceResult, error) {
	policies, err := e.store.ListPolicies(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("retention: list policies: %w", err)
	}

	// Security-critical: drop what the caller does not own before any policy
	// reads or purges a single event.
	policies = slices.DeleteFunc(policies, func(p *Policy) bool {
		return p == nil || (keep != nil && !keep(p))
	})

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
		}
		// A policy can fail part-way and still have purged something (a
		// withheld event does not stop the rest of its batch), so count
		// whatever it reports either way.
		if policyResult == nil {
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
	if policy.AppID == "" {
		return nil, ErrPolicyWithoutApp
	}

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

	// Retention records are never purged, whatever the policy. Stores already
	// leave them out of EventsOlderThan; this holds the line for one that
	// does not.
	events = slices.DeleteFunc(events, func(ev *audit.Event) bool {
		return ev.Category == audit.CategoryRetention
	})

	if len(events) == 0 {
		return result, nil
	}

	// Record the purge in the chain before anything is deleted, and from then
	// on act only on what was recorded. recordErr is returned after the
	// recorded events are purged: withheld or unrecorded events stay put, and
	// the ones already written into a record are safe to remove.
	var recordErr error
	switch {
	case e.recorder != nil:
		var recorded []id.ID
		recorded, recordErr = e.recorder.RecordRetention(ctx, audit.RetentionRef{
			PolicyID: policy.ID.String(),
			Category: policy.Category,
		}, events)
		events = onlyRecorded(events, recorded)
		if len(events) == 0 {
			if recordErr != nil {
				return result, fmt.Errorf("record retention: %w", recordErr)
			}
			return result, nil
		}
	case !e.unrecorded:
		return nil, ErrNoChainRecorder
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

		if archiveErr := e.store.RecordArchive(ctx, archive); archiveErr != nil {
			return nil, fmt.Errorf("record archive: %w", archiveErr)
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

	if recordErr != nil {
		return result, fmt.Errorf("record retention: %w", recordErr)
	}
	return result, nil
}

// onlyRecorded keeps the events whose IDs the recorder returned.
func onlyRecorded(events []*audit.Event, recorded []id.ID) []*audit.Event {
	keep := make(map[id.ID]bool, len(recorded))
	for _, rid := range recorded {
		keep[rid] = true
	}
	return slices.DeleteFunc(events, func(ev *audit.Event) bool { return !keep[ev.ID] })
}
