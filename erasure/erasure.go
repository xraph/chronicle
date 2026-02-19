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
}

// ListOpts defines pagination options for listing erasure records.
type ListOpts struct {
	Limit  int
	Offset int
}
