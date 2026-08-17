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

	// ListErasures returns erasure records matching opts, scoped before
	// pagination.
	ListErasures(ctx context.Context, opts ListOpts) ([]*Erasure, error)

	// CountErasures returns the number of erasure records in the given scope.
	// Callers wanting a total must use this rather than len(ListErasures(...)),
	// which is bounded by the list's limit and loads every row to count it.
	CountErasures(ctx context.Context, s Scope) (int64, error)

	// CountBySubject returns the number of events for a subject within the
	// query's scope. Implementations must honour the scope: an unscoped count
	// reveals how much data other tenants hold on that subject.
	CountBySubject(ctx context.Context, q SubjectQuery) (int64, error)

	// MarkErased flags a subject's events as erased within the query's scope.
	// Implementations must honour the scope: an unscoped update lets any caller
	// tamper with every tenant's audit records.
	MarkErased(ctx context.Context, q SubjectQuery, erasureID id.ID) (int64, error)
}
