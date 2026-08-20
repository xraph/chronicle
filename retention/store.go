package retention

import (
	"context"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
)

// Store manages retention policies and archives.
type Store interface {
	// SavePolicy persists a retention policy. A policy is unique per
	// (AppID, TenantID, Category); saving one must never overwrite or take
	// ownership of another scope's policy for the same category.
	SavePolicy(ctx context.Context, p *Policy) error

	// GetPolicy returns a retention policy by ID. Callers serving a request
	// must check the returned policy's scope before acting on it.
	GetPolicy(ctx context.Context, policyID id.ID) (*Policy, error)

	// ListPolicies returns retention policies matching opts. Scope filtering is
	// applied before pagination.
	ListPolicies(ctx context.Context, opts ListPoliciesOpts) ([]*Policy, error)

	// DeletePolicy removes a retention policy by ID.
	DeletePolicy(ctx context.Context, policyID id.ID) error

	// EventsOlderThan returns events the given query selects: older than
	// q.Before, in q.Category, and belonging to q.Scope. Implementations must
	// honour the scope — an unscoped purge deletes every tenant's history.
	EventsOlderThan(ctx context.Context, q PurgeQuery) ([]*audit.Event, error)

	// PurgeEvents permanently deletes events by IDs (only used by retention enforcer).
	PurgeEvents(ctx context.Context, eventIDs []id.ID) (int64, error)

	// RecordArchive records that a batch of events was archived.
	RecordArchive(ctx context.Context, a *Archive) error

	// ListArchives returns archive records matching opts, scoped before
	// pagination.
	ListArchives(ctx context.Context, opts ListOpts) ([]*Archive, error)
}
