package erasure

import (
	"context"

	"github.com/xraph/chronicle/id"
)

// Store manages GDPR erasure records.
type Store interface {
	// RecordErasure persists an erasure event.
	RecordErasure(ctx context.Context, e *Erasure) error

	// CompleteErasure writes an erasure's outcome and sets its status to
	// StatusCompleted. It returns chronicle.ErrErasureNotFound when no record
	// has that ID.
	CompleteErasure(ctx context.Context, erasureID id.ID, o Outcome) error

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

	// MarkErased flags a subject's events as erased within the query's scope
	// and points them at erasureID. Implementations must honour the scope: an
	// unscoped update lets any caller tamper with every tenant's audit records.
	//
	// Events already marked are marked again and re-pointed, and count towards
	// the result. That is what lets a retry after a failed erasure take over
	// every event the failed attempt reached.
	MarkErased(ctx context.Context, q SubjectQuery, erasureID id.ID) (int64, error)

	// SubjectKeyUsage groups a subject's events by app, tenant, encryption key
	// ID and erased flag, across every app and tenant, with a count for each
	// group. Events that were never sealed come back with an empty key ID.
	//
	// It is unscoped on purpose. Before keys were scoped, a subject's events in
	// different tenants were sealed under one shared key, and the erasure
	// service has to see every scope depending on that key before it can decide
	// whether destroying it is safe. That makes the result exactly what
	// CountBySubject's scoping exists to hide, so it is for trusted in-process
	// use only and must never be returned to a caller.
	SubjectKeyUsage(ctx context.Context, subjectID string) ([]KeyUsage, error)
}
