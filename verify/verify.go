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

	// HeadSeq and HeadHash are the stream's recorded head, supplied by the
	// caller because it already holds the stream row. They are what lets
	// verification notice a truncated tail: without them, deleting the newest
	// events passes on every range you think to ask about.
	HeadSeq  uint64
	HeadHash string
}

// Level grades how much a range's integrity actually rests on. The four are
// ordered: each implies the ones below it.
//
// A single boolean cannot express this, because assurance varies inside one
// stream. A chain migrated last month is unkeyed below its pin and keyed above
// it, and signed only as far as its last checkpoint. Flattening that into a
// green tick is what makes an auditor stop trusting the tool.
type Level string

const (
	// LevelUnkeyed means digests are reproducible by anyone who can read the
	// store. Detects corruption, not tampering.
	LevelUnkeyed Level = "unkeyed"

	// LevelKeyed means digests depend on key material the store does not hold.
	LevelKeyed Level = "keyed"

	// LevelSigned means a signed checkpoint covers the range, so a rewrite
	// after the checkpoint was taken is provable.
	LevelSigned Level = "signed"

	// LevelAnchored means a covering checkpoint was also confirmed from an
	// external publisher. Nothing emits this yet; external anchoring is the
	// next piece of work.
	LevelAnchored Level = "anchored"
)

// LevelRank orders the levels so callers can compare assurance.
func LevelRank(l Level) int {
	switch l {
	case LevelAnchored:
		return 3
	case LevelSigned:
		return 2
	case LevelKeyed:
		return 1
	default:
		return 0
	}
}

// Coverage is the assurance level over one span of sequences.
type Coverage struct {
	FromSeq uint64 `json:"from_seq"`
	ToSeq   uint64 `json:"to_seq"`
	Level   Level  `json:"level"`
	Note    string `json:"note,omitempty"`
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

	// Partial is true when the caller bounded the range rather than verifying
	// genesis to head.
	Partial bool `json:"partial,omitempty"`

	// HeadMatch is whether the last verified hash equals the stream's recorded
	// head hash. False on a truncated chain.
	HeadMatch bool `json:"head_match"`

	// HeadSeq is the stream's recorded head at verification time.
	HeadSeq uint64 `json:"head_seq"`

	// Coverage grades assurance by span. Read it rather than Valid alone.
	Coverage []Coverage `json:"coverage,omitempty"`
}

// gradeCoverage grades assurance across the verified span.
//
// Below the pin's Since the events predate it and were resolved tolerantly, so
// they rest on an unkeyed digest whatever the stream is pinned to now.
func gradeCoverage(input *Input, fromSeq, toSeq uint64) []Coverage {
	pinned := LevelUnkeyed
	if hash.Rank(input.Pin.Scheme) >= hash.Rank(hash.SchemeHMAC) {
		pinned = LevelKeyed
	}

	if input.Pin.Since <= fromSeq {
		return []Coverage{{FromSeq: fromSeq, ToSeq: toSeq, Level: pinned}}
	}
	if input.Pin.Since > toSeq {
		return []Coverage{{
			FromSeq: fromSeq, ToSeq: toSeq, Level: LevelUnkeyed,
			Note: "entirely below the stream's scheme pin; resolved tolerantly",
		}}
	}
	return []Coverage{
		{
			FromSeq: fromSeq, ToSeq: input.Pin.Since - 1, Level: LevelUnkeyed,
			Note: "below the stream's scheme pin; resolved tolerantly",
		},
		{FromSeq: input.Pin.Since, ToSeq: toSeq, Level: pinned},
	}
}
