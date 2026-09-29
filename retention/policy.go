// Package retention defines retention policy and archive entities.
package retention

import (
	"time"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/id"
)

// Policy defines how long events of a given category are retained.
//
// A policy is owned by exactly one (AppID, TenantID) pair and may only ever
// purge events belonging to that pair. An empty TenantID means the policy
// covers the app's untenanted events, and nothing recorded under any tenant.
// Tenants do not inherit an app-level policy: only a tenant's own policies
// purge its events.
type Policy struct {
	chronicle.Entity
	ID       id.ID         `json:"id"`
	Category string        `json:"category"` // "*" for default
	Duration time.Duration `json:"duration"`
	Archive  bool          `json:"archive"` // archive before purge?
	AppID    string        `json:"app_id"`
	TenantID string        `json:"tenant_id,omitempty"`
}

// Scope identifies the owner of retention policies, archives, and the events a
// policy is allowed to purge.
type Scope struct {
	AppID    string `json:"app_id,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
}

// Scope returns the policy's owning scope.
func (p *Policy) Scope() Scope {
	return Scope{AppID: p.AppID, TenantID: p.TenantID}
}

// IsZero reports whether the scope names no app and no tenant. When listing
// policies or archives a zero scope matches everything, so it must only be
// used by trusted in-process callers such as the background retention
// scheduler. A PurgeQuery's scope never works that way: see PurgeQuery.
func (s Scope) IsZero() bool { return s.AppID == "" && s.TenantID == "" }

// PurgeQuery selects the events a retention policy may act on.
type PurgeQuery struct {
	// Scope is the policy's owner, and it matches exactly. An empty TenantID
	// selects the app's untenanted events only, and an empty AppID selects
	// events recorded with no app. Neither is a wildcard, unlike the list
	// filters, because a purge cannot be undone.
	Scope

	// Category is the event category the policy governs.
	Category string `json:"category"`

	// Before selects events with a timestamp strictly older than this.
	Before time.Time `json:"before"`

	// Limit bounds how many events are loaded in one pass. Zero means
	// DefaultPurgeBatchSize; a negative value means unbounded.
	Limit int `json:"limit,omitempty"`
}

// DefaultPurgeBatchSize bounds how many events one retention pass loads into
// memory, so purging a large backlog does not have to fit in RAM all at once.
const DefaultPurgeBatchSize = 5000

// EffectiveLimit resolves 0 to DefaultPurgeBatchSize and negatives to 0
// (meaning "no bound").
func (q PurgeQuery) EffectiveLimit() int {
	switch {
	case q.Limit == 0:
		return DefaultPurgeBatchSize
	case q.Limit < 0:
		return 0
	default:
		return q.Limit
	}
}
