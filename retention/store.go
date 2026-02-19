package retention

import (
	"context"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
)

// Store manages retention policies and archives.
type Store interface {
	// SavePolicy persists a retention policy.
	SavePolicy(ctx context.Context, p *Policy) error

	// GetPolicy returns a retention policy by ID.
	GetPolicy(ctx context.Context, policyID id.ID) (*Policy, error)

	// ListPolicies returns all retention policies.
	ListPolicies(ctx context.Context) ([]*Policy, error)

	// DeletePolicy removes a retention policy.
	DeletePolicy(ctx context.Context, policyID id.ID) error

	// EventsOlderThan returns events older than a given time for a category.
	EventsOlderThan(ctx context.Context, category string, before time.Time) ([]*audit.Event, error)

	// PurgeEvents permanently deletes events by IDs (only used by retention enforcer).
	PurgeEvents(ctx context.Context, eventIDs []id.ID) (int64, error)

	// RecordArchive records that a batch of events was archived.
	RecordArchive(ctx context.Context, a *Archive) error

	// ListArchives returns archive records.
	ListArchives(ctx context.Context, opts ListOpts) ([]*Archive, error)
}
