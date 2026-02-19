// Package verify provides hash chain verification types and logic.
package verify

import "github.com/xraph/chronicle/id"

// Input defines the parameters for a chain verification request.
type Input struct {
	StreamID id.ID
	FromSeq  uint64
	ToSeq    uint64
	AppID    string
	TenantID string
}

// Report is the result of a hash chain verification.
type Report struct {
	Valid      bool     `json:"valid"`
	Verified   int64    `json:"verified"`
	Gaps       []uint64 `json:"gaps"`
	Tampered   []uint64 `json:"tampered"`
	FirstEvent uint64   `json:"first_event"`
	LastEvent  uint64   `json:"last_event"`
}
