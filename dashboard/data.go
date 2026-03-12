package dashboard

import (
	"context"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/store"
)

// fetchTotalEventCount returns the total number of audit events.
func fetchTotalEventCount(ctx context.Context, s store.Store) int64 {
	count, err := s.Count(ctx, &audit.CountQuery{})
	if err != nil {
		return 0
	}
	return count
}

// fetchCriticalEventCount returns the number of critical events in the last 30 days.
func fetchCriticalEventCount(ctx context.Context, s store.Store) int64 {
	now := time.Now()
	thirtyDaysAgo := now.AddDate(0, 0, -30)
	result, err := s.Query(ctx, &audit.Query{
		After:    thirtyDaysAgo,
		Before:   now,
		Severity: []string{"critical"},
		Limit:    1,
	})
	if err != nil {
		return 0
	}
	return result.Total
}

// fetchFailedEventCount returns the number of failed/denied events in the last 30 days.
func fetchFailedEventCount(ctx context.Context, s store.Store) int64 {
	now := time.Now()
	thirtyDaysAgo := now.AddDate(0, 0, -30)
	result, err := s.Query(ctx, &audit.Query{
		After:   thirtyDaysAgo,
		Before:  now,
		Outcome: []string{"failure", "denied"},
		Limit:   1,
	})
	if err != nil {
		return 0
	}
	return result.Total
}

// fetchErasureCount returns the total number of erasure records.
func fetchErasureCount(ctx context.Context, s store.Store) int {
	erasures, err := s.ListErasures(ctx, erasure.ListOpts{Limit: 10000})
	if err != nil {
		return 0
	}
	return len(erasures)
}

// fetchRecentEvents returns the most recent audit events.
func fetchRecentEvents(ctx context.Context, s store.Store, limit int) []*audit.Event {
	result, err := s.Query(ctx, &audit.Query{
		Limit: limit,
		Order: "desc",
	})
	if err != nil {
		return nil
	}
	return result.Events
}

// fetchRecentCriticalEvents returns the most recent critical severity events.
func fetchRecentCriticalEvents(ctx context.Context, s store.Store, limit int) []*audit.Event {
	result, err := s.Query(ctx, &audit.Query{
		Severity: []string{"critical"},
		Limit:    limit,
		Order:    "desc",
	})
	if err != nil {
		return nil
	}
	return result.Events
}

// fetchEvents returns events matching the given query.
func fetchEvents(ctx context.Context, s store.Store, q *audit.Query) ([]*audit.Event, int64, error) {
	result, err := s.Query(ctx, q)
	if err != nil {
		return nil, 0, err
	}
	return result.Events, result.Total, nil
}

// fetchErasures returns erasure records with the given options.
func fetchErasures(ctx context.Context, s store.Store, opts erasure.ListOpts) ([]*erasure.Erasure, error) {
	return s.ListErasures(ctx, opts)
}

// fetchPolicies returns all retention policies.
func fetchPolicies(ctx context.Context, s store.Store) ([]*retention.Policy, error) {
	return s.ListPolicies(ctx)
}

// fetchArchives returns archive records with the given options.
func fetchArchives(ctx context.Context, s store.Store, opts retention.ListOpts) ([]*retention.Archive, error) {
	return s.ListArchives(ctx, opts)
}

// fetchReports returns compliance reports with the given options.
func fetchReports(ctx context.Context, s store.Store, opts compliance.ListOpts) ([]*compliance.Report, error) {
	return s.ListReports(ctx, opts)
}
