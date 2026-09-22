// Package keys supplies the key material that keyed digests and signed
// checkpoints depend on.
//
// It is deliberately separate from crypto.KeyStore. That store holds
// per-subject erasure keys, which exist to be destroyed; these keys are per
// deployment and exist to be retained and rotated. Sharing one store would mean
// a subject exercising their right to erasure could take out the key needed to
// verify a five-year-old event.
//
// # Retiring and revoking are different things
//
// Retiring a key stops it signing anything new. Everything it already signed
// stays verifiable, which is exactly what makes ordinary rotation safe: add the
// new key, move the active flag, leave the old entry in place, and the events
// written under it keep passing verification for as long as you keep them.
// Clear [Provider.Current] moves on, [Provider.ByID] does not.
//
// Revoking a key says the key itself is no longer trustworthy, which is what
// you reach for when one leaks. Anyone holding a leaked key can rewrite every
// event in the store, relabel hash_key_id back to that key, recompute, and get
// a clean verification: the digests really do check out, because they were
// produced with a key the provider recognises. Retiring the key does nothing
// about that, since ByID still resolves it. Revoking it makes ByID refuse with
// [ErrKeyRevoked], so verification errors loudly instead of quietly accepting
// a forgery.
//
// The cost is deliberate and worth stating plainly: revoking a key makes every
// event genuinely signed with it unverifiable too, because nothing can tell the
// honest ones from the forged ones. That is the point. A compromised key means
// the evidence it produced no longer proves anything, and the report should say
// so rather than show a green tick. Revoke on compromise, retire on schedule.
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

// Ed25519KeySize is the required length of a UseCheckpointSig key. It is the
// full ed25519 private key, which carries its own public half in the trailing
// 32 bytes, so a verifier needs nothing else to check a signature.
const Ed25519KeySize = 64

// Sentinel errors.
var (
	// ErrKeyNotFound is returned when no key carries the requested ID.
	ErrKeyNotFound = errors.New("keys: key not found")

	// ErrNoActiveKey is returned when no key is marked active for a use.
	ErrNoActiveKey = errors.New("keys: no active key for use")

	// ErrKeyRevoked is returned when a key exists but has been marked revoked.
	//
	// It is distinct from ErrKeyNotFound on purpose. Not found means the
	// deployment has never heard of this key, which usually points at a
	// truncated keyset or a version skew. Revoked means the deployment knows
	// exactly which key this is and has declared its output worthless, so an
	// artifact naming it is either forged with a leaked key or predates the
	// revocation. Callers surface it as a verification failure, never as a pass.
	ErrKeyRevoked = errors.New("keys: key is revoked")
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
	//
	// A revoked key is refused with [ErrKeyRevoked] rather than returned. That
	// is what makes revocation mean anything: without it, whoever holds a leaked
	// key can relabel every event to that key ID, recompute, and verify clean
	// long after the key was rotated away.
	ByID(ctx context.Context, keyID string) (key []byte, err error)
}
