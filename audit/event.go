// Package audit defines the core audit event types and store interface.
package audit

import (
	"time"

	"github.com/xraph/chronicle/id"
)

// Severity levels for audit events.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Outcome values for audit events.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeDenied  = "denied"
)

// Event is the universal audit event format.
// Append-only — once recorded, events are immutable.
type Event struct {
	// Identity
	ID        id.ID     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Sequence  uint64    `json:"sequence"`

	// Hash chain
	Hash     string `json:"hash"`
	PrevHash string `json:"prev_hash"`
	StreamID id.ID  `json:"stream_id"`

	// Scope (automatically extracted from forge.Scope in ctx)
	AppID    string `json:"app_id"`
	TenantID string `json:"tenant_id,omitempty"`
	UserID   string `json:"user_id,omitempty"`
	IP       string `json:"ip,omitempty"`

	// What happened
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Category string `json:"category"`

	// Details
	ResourceID string         `json:"resource_id,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	Outcome    string         `json:"outcome"`
	Severity   string         `json:"severity"`
	Reason     string         `json:"reason,omitempty"`

	// GDPR (crypto-erasure support)
	SubjectID       string `json:"subject_id,omitempty"`
	EncryptionKeyID string `json:"encryption_key_id,omitempty"`

	// Erasure state (set by retention/GDPR engine, never by caller)
	Erased    bool       `json:"erased,omitempty"`
	ErasedAt  *time.Time `json:"erased_at,omitempty"`
	ErasureID string     `json:"erasure_id,omitempty"`
}
