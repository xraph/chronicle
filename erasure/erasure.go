// Package erasure defines GDPR crypto-erasure entities and store interface.
package erasure

import (
	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/id"
)

// Erasure records a GDPR erasure event.
type Erasure struct {
	chronicle.Entity
	ID             id.ID  `json:"id"`
	SubjectID      string `json:"subject_id"`
	Reason         string `json:"reason"`
	RequestedBy    string `json:"requested_by"`
	EventsAffected int64  `json:"events_affected"`
	KeyDestroyed   bool   `json:"key_destroyed"`
	AppID          string `json:"app_id"`
	TenantID       string `json:"tenant_id"`
}

// Input is the request to erase a subject's data.
type Input struct {
	SubjectID   string `json:"subject_id" validate:"required"`
	Reason      string `json:"reason" validate:"required"`
	RequestedBy string `json:"requested_by" validate:"required"`
}

// Result is the outcome of an erasure operation.
type Result struct {
	ID             id.ID  `json:"id"`
	SubjectID      string `json:"subject_id"`
	EventsAffected int64  `json:"events_affected"`
	KeyDestroyed   bool   `json:"key_destroyed"`

	// LegacyKeyRetained is set when some of the erased events were sealed
	// before keys were scoped, under a key that live events in another app or
	// tenant still depend on. The events are marked erased and no read path
	// will show their payload, but the key was kept, so KeyDestroyed is false.
	// The key goes the first time an erasure finds no other scope still
	// holding unerased events under it. See Service.Erase.
	LegacyKeyRetained bool `json:"legacy_key_retained,omitempty"`
}

// Scope identifies the app and tenant an erasure operation is confined to.
//
// A zero Scope matches every app and tenant. Only trusted in-process callers
// may use one: erasure records carry subject IDs and request reasons, and
// MarkErased mutates events, so an unscoped call both leaks and tampers across
// tenants.
type Scope struct {
	AppID    string `json:"app_id,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
}

// IsZero reports whether the scope names no app and no tenant.
func (s Scope) IsZero() bool { return s.AppID == "" && s.TenantID == "" }

// ListOpts defines pagination and scope options for listing erasure records.
//
// Scope is applied by the store, before LIMIT/OFFSET: filtering after
// pagination would silently hide a caller's own records behind another
// tenant's.
type ListOpts struct {
	Scope

	Limit  int
	Offset int
}

// SubjectQuery identifies a data subject within a scope.
type SubjectQuery struct {
	Scope

	SubjectID string `json:"subject_id"`
}

// covers reports whether an event in the given app and tenant falls inside the
// scope, using the same rule every store applies: an empty field means "any".
func (s Scope) covers(appID, tenantID string) bool {
	if s.AppID != "" && appID != s.AppID {
		return false
	}
	if s.TenantID != "" && tenantID != s.TenantID {
		return false
	}
	return true
}

// KeyUsage counts one subject's events that share an app and tenant, the key
// they were sealed under, and whether they are already marked erased.
type KeyUsage struct {
	Scope

	EncryptionKeyID string `json:"encryption_key_id"`
	Erased          bool   `json:"erased"`
	Events          int64  `json:"events"`
}
