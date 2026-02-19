package audit

import (
	"context"

	"github.com/xraph/chronicle/id"
)

// Store is the primary event store interface.
// Events are append-only — no Update or Delete exists.
type Store interface {
	// Append persists a single event.
	Append(ctx context.Context, event *Event) error

	// AppendBatch persists a batch of events atomically.
	AppendBatch(ctx context.Context, events []*Event) error

	// Get returns a single event by ID.
	Get(ctx context.Context, eventID id.ID) (*Event, error)

	// Query returns events matching filters, scoped to tenant.
	Query(ctx context.Context, q *Query) (*QueryResult, error)

	// Aggregate returns grouped counts/stats for analytics.
	Aggregate(ctx context.Context, q *AggregateQuery) (*AggregateResult, error)

	// ByUser returns events for a specific user within a time range.
	ByUser(ctx context.Context, userID string, opts TimeRange) (*QueryResult, error)

	// Count returns the total number of events matching filters.
	Count(ctx context.Context, q *CountQuery) (int64, error)

	// LastSequence returns the highest sequence number for a stream.
	LastSequence(ctx context.Context, streamID id.ID) (uint64, error)

	// LastHash returns the hash of the most recent event in a stream.
	LastHash(ctx context.Context, streamID id.ID) (string, error)
}
