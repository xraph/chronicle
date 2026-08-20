// Package sealedstore decrypts sealed audit events on the way out of a store.
//
// It exists so every consumer — the admin API, the dashboard, compliance
// reports, and Chronicle's own query methods — sees readable events without each
// having to remember to decrypt. Encryption happens earlier, in
// Chronicle.Record, because the hash has to cover the stored bytes.
package sealedstore

import (
	"context"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/crypto"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/store"
)

// Store wraps a store and decrypts events on the display read paths.
//
// Get, Query and ByUser return opened events. EventRange deliberately does not:
// it feeds hash verification, which recomputes the digest over what was stored,
// so handing it decrypted fields would make every sealed event report as
// tampered. GetStored exposes the same stored form for single-event verification.
//
// Every other read is forwarded unchanged, which is the right default. Notably
// EventsOlderThan stays sealed: retention archives those bytes to cold storage
// before deleting the rows, and writing decrypted copies there would defeat the
// erasure the encryption exists to provide.
//
// That split is the whole reason this is a decorator rather than a change inside
// each backend: there is exactly one place to reason about which reads are for
// display and which are for proof.
type Store struct {
	store.Store

	sealer *crypto.Sealer
}

// Compile-time checks: the wrapper is still a full store, and it advertises the
// stored-form reader that verification needs.
var (
	_ store.Store            = (*Store)(nil)
	_ chronicle.StoredReader = (*Store)(nil)
)

// New wraps s so sealed events are decrypted on display reads.
func New(s store.Store, sealer *crypto.Sealer) *Store {
	return &Store{Store: s, sealer: sealer}
}

// Get returns a single event with its payload decrypted.
func (s *Store) Get(ctx context.Context, eventID id.ID) (*audit.Event, error) {
	event, err := s.Store.Get(ctx, eventID)
	if err != nil {
		return nil, err
	}
	return s.openCopy(event)
}

// GetStored returns a single event exactly as persisted, for hash verification.
func (s *Store) GetStored(ctx context.Context, eventID id.ID) (*audit.Event, error) {
	return s.Store.Get(ctx, eventID)
}

// Query returns matching events with their payloads decrypted.
func (s *Store) Query(ctx context.Context, q *audit.Query) (*audit.QueryResult, error) {
	result, err := s.Store.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	return s.openResult(result)
}

// ByUser returns a user's events with their payloads decrypted.
func (s *Store) ByUser(
	ctx context.Context, userID string, opts audit.TimeRange,
) (*audit.QueryResult, error) {
	result, err := s.Store.ByUser(ctx, userID, opts)
	if err != nil {
		return nil, err
	}
	return s.openResult(result)
}

// openCopy decrypts into a copy, leaving the caller's event untouched.
//
// Decrypting in place is unsafe: a store may hand back a pointer into its own
// state (the in-memory one does), so opening would overwrite the stored
// ciphertext with plaintext. The digest covers the ciphertext, so that would make
// the event read as tampered and quietly undo the erasure.
//
// A shallow copy is enough because Open only ever assigns whole values — it never
// mutates the metadata map in place.
func (s *Store) openCopy(event *audit.Event) (*audit.Event, error) {
	if event == nil {
		return nil, nil
	}

	clone := *event
	if err := s.sealer.Open(&clone); err != nil {
		return nil, err
	}
	return &clone, nil
}

// openResult decrypts every event in a result into copies.
func (s *Store) openResult(result *audit.QueryResult) (*audit.QueryResult, error) {
	if result == nil {
		return nil, nil
	}

	opened := make([]*audit.Event, 0, len(result.Events))
	for _, event := range result.Events {
		clone, err := s.openCopy(event)
		if err != nil {
			return nil, err
		}
		opened = append(opened, clone)
	}

	out := *result
	out.Events = opened
	return &out, nil
}
