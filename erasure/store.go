package erasure

import (
	"context"

	"github.com/xraph/chronicle/id"
)

// Store manages GDPR erasure records.
type Store interface {
	// RecordErasure persists an erasure event.
	RecordErasure(ctx context.Context, e *Erasure) error

	// GetErasure returns an erasure record by ID.
	GetErasure(ctx context.Context, erasureID id.ID) (*Erasure, error)

	// ListErasures returns erasure records, optionally filtered.
	ListErasures(ctx context.Context, opts ListOpts) ([]*Erasure, error)

	// CountBySubject returns number of events for a subject.
	CountBySubject(ctx context.Context, subjectID string) (int64, error)

	// MarkErased updates events to show [ERASED] for a given subject.
	MarkErased(ctx context.Context, subjectID string, erasureID id.ID) (int64, error)
}
