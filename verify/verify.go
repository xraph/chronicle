// Package verify provides hash chain verification types and logic.
package verify

import (
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
)

// Input defines the parameters for a chain verification request.
type Input struct {
	StreamID id.ID
	FromSeq  uint64
	ToSeq    uint64
	AppID    string
	TenantID string

	// Pin is the stream's declared scheme and the sequence it applies from.
	// A zero Pin disables downgrade detection, which is only correct for
	// callers that genuinely have no stream in hand.
	Pin hash.Pin
}

// Report is the result of a hash chain verification.
type Report struct {
	Valid      bool     `json:"valid"`
	Verified   int64    `json:"verified"`
	Gaps       []uint64 `json:"gaps"`
	Tampered   []uint64 `json:"tampered"`
	FirstEvent uint64   `json:"first_event"`
	LastEvent  uint64   `json:"last_event"`

	// Downgrades are sequences whose event claims a weaker digest scheme than
	// its stream pins at that point. These are tampering, not old events.
	Downgrades []uint64 `json:"downgrades,omitempty"`

	// Tolerant are sequences resolved through the pre-migration fallback,
	// where the scheme was not recorded and had to be guessed.
	Tolerant []uint64 `json:"tolerant,omitempty"`
}
