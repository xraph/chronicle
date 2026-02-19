// Package memory provides an in-memory implementation of the Chronicle store.
// It is intended for unit testing and development only.
package memory

import (
	"context"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/stream"
	"github.com/xraph/chronicle/verify"
)

// Compile-time interface checks.
var (
	_ audit.Store            = (*Store)(nil)
	_ stream.Store           = (*Store)(nil)
	_ verify.Store           = (*Store)(nil)
	_ erasure.Store          = (*Store)(nil)
	_ retention.Store        = (*Store)(nil)
	_ compliance.ReportStore = (*Store)(nil)
)

// Store is an in-memory implementation of all Chronicle store interfaces.
type Store struct {
	mu       sync.RWMutex
	events   []*audit.Event
	streams  []*stream.Stream
	erasures []*erasure.Erasure
	policies []*retention.Policy
	archives []*retention.Archive
	reports  []*compliance.Report
	closed   bool
}

// New creates a new in-memory store.
func New() *Store {
	return &Store{}
}

// ──────────────────────────────────────────────────
// Lifecycle
// ──────────────────────────────────────────────────

// Migrate is a no-op for the memory store.
func (s *Store) Migrate(_ context.Context) error { return nil }

// Ping is a no-op for the memory store.
func (s *Store) Ping(_ context.Context) error { return nil }

// Close marks the store as closed.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

// ──────────────────────────────────────────────────
// audit.Store
// ──────────────────────────────────────────────────

// Append persists a single event.
func (s *Store) Append(_ context.Context, event *audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}

// AppendBatch persists a batch of events atomically.
func (s *Store) AppendBatch(_ context.Context, events []*audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, events...)
	return nil
}

// Get returns a single event by ID.
func (s *Store) Get(_ context.Context, eventID id.ID) (*audit.Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	idStr := eventID.String()
	for _, e := range s.events {
		if e.ID.String() == idStr {
			return e, nil
		}
	}
	return nil, chronicle.ErrEventNotFound
}

// Query returns events matching filters.
func (s *Store) Query(_ context.Context, q *audit.Query) (*audit.QueryResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var matched []*audit.Event
	for _, e := range s.events {
		if matchesQuery(e, q) {
			matched = append(matched, e)
		}
	}

	// Sort by timestamp
	if q.Order == "asc" {
		sort.Slice(matched, func(i, j int) bool {
			return matched[i].Timestamp.Before(matched[j].Timestamp)
		})
	} else {
		sort.Slice(matched, func(i, j int) bool {
			return matched[i].Timestamp.After(matched[j].Timestamp)
		})
	}

	total := int64(len(matched))

	// Apply pagination
	if q.Offset > 0 && q.Offset < len(matched) {
		matched = matched[q.Offset:]
	} else if q.Offset >= len(matched) {
		matched = nil
	}

	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}

	hasMore := len(matched) > limit
	if hasMore {
		matched = matched[:limit]
	}

	return &audit.QueryResult{
		Events:  matched,
		Total:   total,
		HasMore: hasMore,
	}, nil
}

// Aggregate returns grouped counts/stats.
func (s *Store) Aggregate(_ context.Context, q *audit.AggregateQuery) (*audit.AggregateResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	groups := make(map[string]*audit.AggregateGroup)
	var total int64

	for _, e := range s.events {
		if !matchesAggregateScope(e, q) {
			continue
		}
		total++

		key := aggregateKey(e, q.GroupBy)
		g, ok := groups[key]
		if !ok {
			g = &audit.AggregateGroup{}
			for _, gb := range q.GroupBy {
				switch gb {
				case "category":
					g.Category = e.Category
				case "action":
					g.Action = e.Action
				case "outcome":
					g.Outcome = e.Outcome
				case "severity":
					g.Severity = e.Severity
				case "resource":
					g.Resource = e.Resource
				}
			}
			groups[key] = g
		}
		g.Count++
	}

	result := make([]audit.AggregateGroup, 0, len(groups))
	for _, g := range groups {
		result = append(result, *g)
	}

	return &audit.AggregateResult{
		Groups: result,
		Total:  total,
	}, nil
}

// ByUser returns events for a specific user within a time range.
func (s *Store) ByUser(_ context.Context, userID string, opts audit.TimeRange) (*audit.QueryResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	matched := make([]*audit.Event, 0, len(s.events))
	for _, e := range s.events {
		if e.UserID != userID {
			continue
		}
		if !opts.After.IsZero() && e.Timestamp.Before(opts.After) {
			continue
		}
		if !opts.Before.IsZero() && e.Timestamp.After(opts.Before) {
			continue
		}
		matched = append(matched, e)
	}

	sort.Slice(matched, func(i, j int) bool {
		return matched[i].Timestamp.After(matched[j].Timestamp)
	})

	return &audit.QueryResult{
		Events:  matched,
		Total:   int64(len(matched)),
		HasMore: false,
	}, nil
}

// Count returns the total number of events matching filters.
func (s *Store) Count(_ context.Context, q *audit.CountQuery) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int64
	for _, e := range s.events {
		if q.AppID != "" && e.AppID != q.AppID {
			continue
		}
		if q.TenantID != "" && e.TenantID != q.TenantID {
			continue
		}
		if q.Category != "" && e.Category != q.Category {
			continue
		}
		if !q.After.IsZero() && e.Timestamp.Before(q.After) {
			continue
		}
		if !q.Before.IsZero() && e.Timestamp.After(q.Before) {
			continue
		}
		count++
	}
	return count, nil
}

// LastSequence returns the highest sequence number for a stream.
func (s *Store) LastSequence(_ context.Context, streamID id.ID) (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	idStr := streamID.String()
	var maxSeq uint64
	for _, e := range s.events {
		if e.StreamID.String() == idStr && e.Sequence > maxSeq {
			maxSeq = e.Sequence
		}
	}
	return maxSeq, nil
}

// LastHash returns the hash of the most recent event in a stream.
func (s *Store) LastHash(_ context.Context, streamID id.ID) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	idStr := streamID.String()
	var maxSeq uint64
	var hash string
	for _, e := range s.events {
		if e.StreamID.String() == idStr && e.Sequence > maxSeq {
			maxSeq = e.Sequence
			hash = e.Hash
		}
	}
	return hash, nil
}

// ──────────────────────────────────────────────────
// stream.Store
// ──────────────────────────────────────────────────

// CreateStream initializes a new hash chain stream.
func (s *Store) CreateStream(_ context.Context, st *stream.Stream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streams = append(s.streams, st)
	return nil
}

// GetStream returns a stream by ID (named to avoid collision with audit.Get).
func (s *Store) GetStream(_ context.Context, streamID id.ID) (*stream.Stream, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	idStr := streamID.String()
	for _, st := range s.streams {
		if st.ID.String() == idStr {
			return st, nil
		}
	}
	return nil, chronicle.ErrStreamNotFound
}

// GetStreamByScope returns the stream for a given app+tenant scope.
func (s *Store) GetStreamByScope(_ context.Context, appID, tenantID string) (*stream.Stream, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, st := range s.streams {
		if st.AppID == appID && st.TenantID == tenantID {
			return st, nil
		}
	}
	return nil, chronicle.ErrStreamNotFound
}

// ListStreams returns all streams.
func (s *Store) ListStreams(_ context.Context, opts stream.ListOpts) ([]*stream.Stream, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*stream.Stream, len(s.streams))
	copy(result, s.streams)

	if opts.Offset > 0 && opts.Offset < len(result) {
		result = result[opts.Offset:]
	}
	if opts.Limit > 0 && opts.Limit < len(result) {
		result = result[:opts.Limit]
	}
	return result, nil
}

// UpdateStreamHead updates the stream's head hash and sequence.
func (s *Store) UpdateStreamHead(_ context.Context, streamID id.ID, hash string, seq uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	idStr := streamID.String()
	for _, st := range s.streams {
		if st.ID.String() == idStr {
			st.HeadHash = hash
			st.HeadSeq = seq
			st.UpdatedAt = time.Now().UTC()
			return nil
		}
	}
	return chronicle.ErrStreamNotFound
}

// ──────────────────────────────────────────────────
// verify.Store
// ──────────────────────────────────────────────────

// EventRange returns events in a sequence range for chain verification.
func (s *Store) EventRange(_ context.Context, streamID id.ID, fromSeq, toSeq uint64) ([]*audit.Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	idStr := streamID.String()
	var result []*audit.Event
	for _, e := range s.events {
		if e.StreamID.String() == idStr && e.Sequence >= fromSeq && e.Sequence <= toSeq {
			result = append(result, e)
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Sequence < result[j].Sequence
	})

	return result, nil
}

// Gaps detects missing sequence numbers in a range.
func (s *Store) Gaps(_ context.Context, streamID id.ID, fromSeq, toSeq uint64) ([]uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	idStr := streamID.String()
	seqSet := make(map[uint64]bool)
	for _, e := range s.events {
		if e.StreamID.String() == idStr && e.Sequence >= fromSeq && e.Sequence <= toSeq {
			seqSet[e.Sequence] = true
		}
	}

	var gaps []uint64
	for seq := fromSeq; seq <= toSeq; seq++ {
		if !seqSet[seq] {
			gaps = append(gaps, seq)
		}
	}
	return gaps, nil
}

// ──────────────────────────────────────────────────
// erasure.Store
// ──────────────────────────────────────────────────

// RecordErasure persists an erasure event.
func (s *Store) RecordErasure(_ context.Context, e *erasure.Erasure) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.erasures = append(s.erasures, e)
	return nil
}

// GetErasure returns an erasure record by ID.
func (s *Store) GetErasure(_ context.Context, erasureID id.ID) (*erasure.Erasure, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	idStr := erasureID.String()
	for _, e := range s.erasures {
		if e.ID.String() == idStr {
			return e, nil
		}
	}
	return nil, chronicle.ErrErasureNotFound
}

// ListErasures returns erasure records.
func (s *Store) ListErasures(_ context.Context, opts erasure.ListOpts) ([]*erasure.Erasure, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*erasure.Erasure, len(s.erasures))
	copy(result, s.erasures)

	if opts.Offset > 0 && opts.Offset < len(result) {
		result = result[opts.Offset:]
	}
	if opts.Limit > 0 && opts.Limit < len(result) {
		result = result[:opts.Limit]
	}
	return result, nil
}

// CountBySubject returns number of events for a subject.
func (s *Store) CountBySubject(_ context.Context, subjectID string) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int64
	for _, e := range s.events {
		if e.SubjectID == subjectID {
			count++
		}
	}
	return count, nil
}

// MarkErased updates events to show [ERASED] for a given subject.
func (s *Store) MarkErased(_ context.Context, subjectID string, erasureID id.ID) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	eidStr := erasureID.String()
	var count int64
	for _, e := range s.events {
		if e.SubjectID == subjectID && !e.Erased {
			e.Erased = true
			e.ErasedAt = &now
			e.ErasureID = eidStr
			count++
		}
	}
	return count, nil
}

// ──────────────────────────────────────────────────
// retention.Store
// ──────────────────────────────────────────────────

// SavePolicy persists a retention policy.
func (s *Store) SavePolicy(_ context.Context, p *retention.Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Update if exists
	idStr := p.ID.String()
	for i, existing := range s.policies {
		if existing.ID.String() == idStr {
			s.policies[i] = p
			return nil
		}
	}
	s.policies = append(s.policies, p)
	return nil
}

// GetPolicy returns a retention policy by ID.
func (s *Store) GetPolicy(_ context.Context, policyID id.ID) (*retention.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	idStr := policyID.String()
	for _, p := range s.policies {
		if p.ID.String() == idStr {
			return p, nil
		}
	}
	return nil, chronicle.ErrPolicyNotFound
}

// ListPolicies returns all retention policies.
func (s *Store) ListPolicies(_ context.Context) ([]*retention.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*retention.Policy, len(s.policies))
	copy(result, s.policies)
	return result, nil
}

// DeletePolicy removes a retention policy.
func (s *Store) DeletePolicy(_ context.Context, policyID id.ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	idStr := policyID.String()
	for i, p := range s.policies {
		if p.ID.String() == idStr {
			s.policies = slices.Delete(s.policies, i, i+1)
			return nil
		}
	}
	return chronicle.ErrPolicyNotFound
}

// EventsOlderThan returns events older than a given time for a category.
func (s *Store) EventsOlderThan(_ context.Context, category string, before time.Time) ([]*audit.Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*audit.Event
	for _, e := range s.events {
		if e.Timestamp.Before(before) {
			if category == "*" || e.Category == category {
				result = append(result, e)
			}
		}
	}
	return result, nil
}

// PurgeEvents permanently deletes events by IDs.
func (s *Store) PurgeEvents(_ context.Context, eventIDs []id.ID) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idSet := make(map[string]bool, len(eventIDs))
	for _, eid := range eventIDs {
		idSet[eid.String()] = true
	}

	var purged int64
	remaining := s.events[:0]
	for _, e := range s.events {
		if idSet[e.ID.String()] {
			purged++
		} else {
			remaining = append(remaining, e)
		}
	}
	s.events = remaining
	return purged, nil
}

// RecordArchive records that a batch of events was archived.
func (s *Store) RecordArchive(_ context.Context, a *retention.Archive) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.archives = append(s.archives, a)
	return nil
}

// ListArchives returns archive records.
func (s *Store) ListArchives(_ context.Context, opts retention.ListOpts) ([]*retention.Archive, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*retention.Archive, len(s.archives))
	copy(result, s.archives)

	if opts.Offset > 0 && opts.Offset < len(result) {
		result = result[opts.Offset:]
	}
	if opts.Limit > 0 && opts.Limit < len(result) {
		result = result[:opts.Limit]
	}
	return result, nil
}

// ──────────────────────────────────────────────────
// compliance.ReportStore
// ──────────────────────────────────────────────────

// SaveReport persists a generated compliance report.
func (s *Store) SaveReport(_ context.Context, r *compliance.Report) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reports = append(s.reports, r)
	return nil
}

// GetReport returns a report by ID.
func (s *Store) GetReport(_ context.Context, reportID id.ID) (*compliance.Report, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	idStr := reportID.String()
	for _, r := range s.reports {
		if r.ID.String() == idStr {
			return r, nil
		}
	}
	return nil, chronicle.ErrReportNotFound
}

// ListReports returns reports.
func (s *Store) ListReports(_ context.Context, opts compliance.ListOpts) ([]*compliance.Report, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*compliance.Report, len(s.reports))
	copy(result, s.reports)

	if opts.Offset > 0 && opts.Offset < len(result) {
		result = result[opts.Offset:]
	}
	if opts.Limit > 0 && opts.Limit < len(result) {
		result = result[:opts.Limit]
	}
	return result, nil
}

// DeleteReport removes a report.
func (s *Store) DeleteReport(_ context.Context, reportID id.ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	idStr := reportID.String()
	for i, r := range s.reports {
		if r.ID.String() == idStr {
			s.reports = slices.Delete(s.reports, i, i+1)
			return nil
		}
	}
	return chronicle.ErrReportNotFound
}

// ──────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────

func matchesQuery(e *audit.Event, q *audit.Query) bool {
	if q.AppID != "" && e.AppID != q.AppID {
		return false
	}
	if q.TenantID != "" && e.TenantID != q.TenantID {
		return false
	}
	if q.UserID != "" && e.UserID != q.UserID {
		return false
	}
	if !q.After.IsZero() && e.Timestamp.Before(q.After) {
		return false
	}
	if !q.Before.IsZero() && e.Timestamp.After(q.Before) {
		return false
	}
	if len(q.Categories) > 0 && !contains(q.Categories, e.Category) {
		return false
	}
	if len(q.Actions) > 0 && !contains(q.Actions, e.Action) {
		return false
	}
	if len(q.Resources) > 0 && !contains(q.Resources, e.Resource) {
		return false
	}
	if len(q.Severity) > 0 && !contains(q.Severity, e.Severity) {
		return false
	}
	if len(q.Outcome) > 0 && !contains(q.Outcome, e.Outcome) {
		return false
	}
	return true
}

func matchesAggregateScope(e *audit.Event, q *audit.AggregateQuery) bool {
	if q.AppID != "" && e.AppID != q.AppID {
		return false
	}
	if q.TenantID != "" && e.TenantID != q.TenantID {
		return false
	}
	if !q.After.IsZero() && e.Timestamp.Before(q.After) {
		return false
	}
	if !q.Before.IsZero() && e.Timestamp.After(q.Before) {
		return false
	}
	return true
}

func aggregateKey(e *audit.Event, groupBy []string) string {
	var parts []string
	for _, gb := range groupBy {
		switch gb {
		case "category":
			parts = append(parts, e.Category)
		case "action":
			parts = append(parts, e.Action)
		case "outcome":
			parts = append(parts, e.Outcome)
		case "severity":
			parts = append(parts, e.Severity)
		case "resource":
			parts = append(parts, e.Resource)
		}
	}
	return strings.Join(parts, "|")
}

func contains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
