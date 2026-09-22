// Package checkpoint records signed statements about where a hash chain stood,
// so that rewriting an event after the fact becomes provable.
//
// A chain of unkeyed digests can be recomputed by anyone who can write to the
// store. Keying the digest raises that bar, but both the event's scheme and its
// stream's pin live in the same database, so an attacker with write access can
// still rewrite both. A checkpoint is different: it asserts that at sequence N
// the chain hash was H, and it is signed, so the assertion cannot be restated
// without the signing key. If the event now at N hashes to something else, the
// chain was rewritten after the checkpoint was taken and the signature proves it.
package checkpoint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/xraph/chronicle/id"
)

// payloadVersion prefixes the signed bytes so the canonical encoding can change
// later without a verifier misreading an old signature.
const payloadVersion = "chronicle-checkpoint/v1"

// Checkpoint is a signed statement about one stream's chain over a sequence
// range.
type Checkpoint struct {
	ID       id.ID `json:"id"`
	StreamID id.ID `json:"stream_id"`

	AppID    string `json:"app_id"`
	TenantID string `json:"tenant_id,omitempty"`

	// FromSeq and ToSeq bound the range this checkpoint covers, inclusive.
	FromSeq uint64 `json:"from_seq"`
	ToSeq   uint64 `json:"to_seq"`

	// FromHash and ToHash are the chain hashes at those boundaries. ToHash is
	// the assertion that matters: recomputing the event at ToSeq must reproduce
	// it, or the chain was rewritten after this checkpoint.
	FromHash string `json:"from_hash"`
	ToHash   string `json:"to_hash"`

	// EventCount is the sequence span this checkpoint covers (ToSeq - FromSeq
	// + 1), not a verified count of rows the store actually holds in that
	// range. CheckpointStream computes it arithmetically from the two
	// sequence numbers it already asserts, without reading a single event;
	// a gap in the range (a missing sequence) is not reflected here and is
	// verification's job (Store.Gaps), not a checkpoint's.
	EventCount int64 `json:"event_count"`

	// PrevCheckpoint is the digest of the preceding checkpoint's signed payload,
	// which is what makes deleting one from the middle detectable. It is empty
	// for a stream's first checkpoint.
	PrevCheckpoint string `json:"prev_checkpoint,omitempty"`

	Algorithm string `json:"algorithm"`
	SignKeyID string `json:"sign_key_id"`
	Signature []byte `json:"signature"`

	// SignedPayload is the exact bytes that were signed. Storing them rather
	// than re-deriving from the columns means a later change to the canonical
	// encoding cannot silently invalidate every historical signature.
	SignedPayload string `json:"signed_payload"`

	CreatedAt time.Time `json:"created_at"`
}

// CanonicalPayload renders the bytes a checkpoint's signature covers.
//
// Every field the checkpoint asserts appears here. A field left out is a field
// an attacker can edit while the signature still verifies.
//
// Variable-length string fields are rendered length-prefixed
// (lengthPrefixed: "<byte-length>:<value>") rather than joined with a bare
// "|". AppID and TenantID are free text from caller scope, so a bare join
// lets a "|" inside one value shift where the reader thinks the next field
// starts: AppID="a", TenantID="b|c" and AppID="a|b", TenantID="c" would
// otherwise render identically. Length-prefixing fixes each field's end at an
// exact byte offset instead of at the next "|", so no embedded separator can
// move a boundary. FromHash, ToHash, PrevCheckpoint, and StreamID get the same
// treatment on the same reasoning, even though today's callers only produce
// hex and TypeID strings for them. FromSeq, ToSeq, EventCount, and CreatedAt
// are left as plain decimal/RFC3339Nano text: none of those formats can
// contain "|", so they cannot shift a boundary either way.
func CanonicalPayload(c *Checkpoint) string {
	return fmt.Sprintf("%s|%s|%s|%s|%d|%d|%s|%s|%d|%s|%s",
		payloadVersion,
		lengthPrefixed(c.StreamID.String()),
		lengthPrefixed(c.AppID),
		lengthPrefixed(c.TenantID),
		c.FromSeq,
		c.ToSeq,
		lengthPrefixed(c.FromHash),
		lengthPrefixed(c.ToHash),
		c.EventCount,
		lengthPrefixed(c.PrevCheckpoint),
		c.CreatedAt.UTC().Format(time.RFC3339Nano),
	)
}

// lengthPrefixed renders s as "<byte-length>:<s>" so that a "|" occurring
// inside s cannot be mistaken by a reader for the payload's field separator.
func lengthPrefixed(s string) string {
	return fmt.Sprintf("%d:%s", len(s), s)
}

// Digest returns the hex SHA-256 of a canonical payload, which is what the next
// checkpoint records as its PrevCheckpoint.
func Digest(payload string) string {
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// ListOpts bounds a checkpoint listing.
type ListOpts struct {
	Limit  int
	Offset int
}
