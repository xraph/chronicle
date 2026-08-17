package retention

import (
	"time"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/id"
)

// Archive records that a batch of events was archived to cold storage.
type Archive struct {
	chronicle.Entity
	ID            id.ID     `json:"id"`
	PolicyID      id.ID     `json:"policy_id"`
	Category      string    `json:"category"`
	EventCount    int64     `json:"event_count"`
	FromTimestamp time.Time `json:"from_timestamp"`
	ToTimestamp   time.Time `json:"to_timestamp"`
	SinkName      string    `json:"sink_name"`
	SinkRef       string    `json:"sink_ref"` // e.g. S3 key
	AppID         string    `json:"app_id"`
	TenantID      string    `json:"tenant_id,omitempty"`
}

// ListOpts defines pagination and scope options for listing archives.
//
// Scope is applied by the store, not by the caller after the fact: filtering
// after LIMIT/OFFSET would silently drop a tenant's rows whenever another
// tenant's archives fill the first page.
type ListOpts struct {
	Scope

	Limit  int
	Offset int
}

// ListPoliciesOpts scopes and bounds a policy listing.
type ListPoliciesOpts struct {
	Scope

	Limit  int
	Offset int
}
