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

	// HeadChecked is whether the tail was compared to a recorded head, or
	// the range resolved empty against a stream that claims one.
	//
	// It is false whenever HeadMatch's zero value cannot be trusted: no head
	// was supplied, or the range was Partial and the comparison was skipped.
	// Read HeadMatch only when HeadChecked is true -- otherwise "false" means
	// "not checked", not "checked and mismatched".
	//
	// The one case where true does not mean two hashes were compared is an
	// empty resolved range with a non-zero HeadSeq. There is no tail to
	// compare, and the report is already invalid: a stream that claims a head
	// and produced no events in range cannot have been verified up to it. So
	// HeadChecked true with HeadMatch false says the tail did not reach the
	// claimed head, which is exactly what happened, rather than pretending a
	// comparison ran.
	HeadChecked bool `json:"head_checked"`

	// HeadSeq is the stream's recorded head at verification time.
	HeadSeq uint64 `json:"head_seq"`

	// Coverage grades assurance by span. Read it rather than Valid alone.
	Coverage []Coverage `json:"coverage,omitempty"`

	// Checkpoints is what each covering checkpoint asserted and whether it held.
	Checkpoints []CheckpointResult `json:"checkpoints,omitempty"`

	// CheckpointsChecked is whether this verification consulted a checkpoint
	// store at all. It is false for a verifier built without one, and for a
	// backend that refuses to hold checkpoints.
	//
	// Checkpoints omits itself when empty, so without this an auditor cannot
	// tell "this stream has no checkpoints" from "nothing looked". Those are
	// very different answers to give someone asking whether a log can be
	// trusted.
	CheckpointsChecked bool `json:"checkpoints_checked"`

	// CheckpointHeadOK is whether the stream's latest checkpoint is
	// consistent with the head the caller claimed. False means a signed
	// checkpoint asserts the chain once reached a sequence past that head, so
	// events have been removed from the tail and the head row moved down to
	// hide it.
	//
	// Read it only when CheckpointHeadChecked is true, for the same reason as
	// HeadMatch/HeadChecked.
	CheckpointHeadOK bool `json:"checkpoint_head_ok"`

	// CheckpointHeadChecked is whether that comparison actually ran. It is
	// false when there is no checkpoint store, no checkpoint for this stream,
	// or no checkpoint whose signature still verifies -- all of which are
	// "no opinion", not "consistent".
	CheckpointHeadChecked bool `json:"checkpoint_head_checked"`
}

// CheckpointResult is what one covering checkpoint asserted and whether it holds.
type CheckpointResult struct {
	ID      string `json:"id"`
	FromSeq uint64 `json:"from_seq"`
	ToSeq   uint64 `json:"to_seq"`

	// SignatureValid is whether the stored payload verifies under the key that
	// signed it. False means the checkpoint was edited after signing.
	SignatureValid bool `json:"signature_valid"`

	// HashMatch is whether the event now at ToSeq still hashes to the recorded
	// ToHash. False means the chain was rewritten after this checkpoint.
	//
	// Read it only when HashChecked is true. CheckpointsInRange overlaps
	// rather than contains, so a covering checkpoint's ToSeq can land outside
	// the range this verification actually fetched; when that happens
	// HashMatch stays at its false zero value, and HashChecked says so, so a
	// caller cannot mistake "not checked" for "checked and mismatched".
	HashMatch bool `json:"hash_match"`

	// HashChecked is whether HashMatch was actually evaluated against a
	// fetched event, as opposed to left at its zero value because ToSeq fell
	// outside the verified range.
	HashChecked bool `json:"hash_checked"`

	// ContinuityOK is whether this checkpoint follows the previous one without
	// a gap. False means a checkpoint was removed.
	//
	// Read it only when ContinuityChecked is true, for the same reason as
	// HashMatch/HashChecked: a checkpoint's immediate predecessor may not be
	// part of what this verification fetched, in which case continuity
	// cannot be determined from what is in hand.
	ContinuityOK bool `json:"continuity_ok"`

	// ContinuityChecked is whether ContinuityOK was actually evaluated. It is
	// true for a stream's first checkpoint (FromSeq 1, empty PrevCheckpoint,
	// which is continuous by definition) and for any checkpoint whose
	// immediate predecessor was also fetched by this verification.
	ContinuityChecked bool `json:"continuity_checked"`

	Note string `json:"note,omitempty"`
}

// gradeCoverage grades assurance across the verified span.
//
// Below the pin's Since the events predate it and were resolved tolerantly, so
// they rest on an unkeyed digest whatever the stream is pinned to now.
func gradeCoverage(input *Input, fromSeq, toSeq uint64) []Coverage {
	pinned := LevelUnkeyed
	if hash.Keyed(input.Pin.Scheme) {
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
