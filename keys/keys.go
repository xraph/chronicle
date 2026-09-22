// Package keys supplies the key material that keyed digests and signed
// checkpoints depend on.
//
// It is deliberately separate from crypto.KeyStore. That store holds
// per-subject erasure keys, which exist to be destroyed; these keys are per
// deployment and exist to be retained and rotated. Sharing one store would mean
// a subject exercising their right to erasure could take out the key needed to
// verify a five-year-old event.
package keys

import (
	"context"
	"errors"
)

// Use identifies what a key is for. Key IDs are unique across all uses, so
// ByID does not need one.
type Use string

const (
	// UseHMAC is the 32-byte symmetric key behind hash.SchemeHMAC.
	UseHMAC Use = "hmac"

	// UseCheckpointSig is the ed25519 private key that signs checkpoints.
	UseCheckpointSig Use = "checkpoint-sig"
)

// HMACKeySize is the required length of a UseHMAC key.
const HMACKeySize = 32

// Sentinel errors.
var (
	// ErrKeyNotFound is returned when no key carries the requested ID.
	ErrKeyNotFound = errors.New("keys: key not found")

	// ErrNoActiveKey is returned when no key is marked active for a use.
	ErrNoActiveKey = errors.New("keys: no active key for use")
)

// Provider supplies key material.
//
// Current is for writing and ByID is for verifying artifacts written under an
// earlier key. Having both is what makes rotation possible: retiring a key
// stops it being used for new digests without making old ones unverifiable.
type Provider interface {
	// Current returns the active key for a use, and its ID.
	Current(ctx context.Context, use Use) (key []byte, keyID string, err error)

	// ByID returns the key with the given ID, active or retired.
	ByID(ctx context.Context, keyID string) (key []byte, err error)
}
