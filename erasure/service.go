package erasure

import (
	"context"
	"errors"
	"fmt"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/crypto"
	"github.com/xraph/chronicle/id"
)

// Service performs GDPR crypto-erasure operations.
type Service struct {
	store    Store
	keyStore crypto.KeyStore
}

// NewService creates a new erasure Service.
func NewService(store Store, keyStore crypto.KeyStore) *Service {
	return &Service{
		store:    store,
		keyStore: keyStore,
	}
}

// Erase performs a GDPR erasure for a subject within the caller's app and
// tenant:
//
//  1. Count the subject's events in scope.
//  2. Record the erasure as pending, with KeyDestroyed false.
//  3. Mark the events erased.
//  4. Destroy the keys those events were sealed under, and no others.
//  5. Complete the record with the outcome.
//
// Destroying keys is the one step that cannot be undone, so it runs only once
// the erasure is on record and the events are marked. If a step fails, Erase
// returns an error naming the erasure and stops. The record stays pending, and
// until step 4 the keys are untouched. If step 4 fails part way, the keys
// that failed to delete survive, the ones that did delete stay deleted, and
// the record still says KeyDestroyed false. If step 5 fails, the keys are gone
// but the record still says pending.
//
// A pending record is the signal to run Erase again for the same subject and
// scope. The retry writes its own record, marks every event again (including
// any the failed attempt reached), deletes the keys again (deleting a missing
// key is not an error) and completes. The pending record stays as the trail of
// the failed attempt.
//
// Everything is confined to the scope. An empty TenantID covers every tenant in
// the app, and an empty AppID and TenantID together cover everything, which is
// the rule the stores apply to CountBySubject and MarkErased. Step 4 follows the
// same rule, so the keys destroyed always belong to exactly the events marked.
//
// # Keys sealed before scoping
//
// Events sealed before this release sit under a key named by the bare subject
// ID, shared by every app and tenant that used that subject ID. Destroying it
// on behalf of one scope destroys the others' data with no record in their
// scope, which is the bug scoping fixed. Keeping it means the erasing scope's
// ciphertext can still be decrypted by anyone holding the key store.
//
// Erase destroys a legacy key only when no other scope still holds unerased
// events sealed under it. Otherwise it marks the caller's events erased as
// usual, keeps the key, and completes the record with KeyDestroyed false and
// LegacyKeyRetained set, which the result reports too. [crypto.Sealer.Open]
// redacts any event flagged erased, so the payload stops being readable through
// Chronicle straight away, but the erasure is not cryptographic until the key
// goes. The key goes the first time any sharing scope erases the subject and
// finds every other scope's legacy events already erased, so running Erase
// again later is how a retained key gets cleaned up.
//
// Which keys to destroy is decided after the events are marked, from a fresh
// read. Other scopes' legacy events only ever go from unerased to erased, so a
// retry can move from keeping the legacy key to destroying it, never back.
//
// Re-sealing the caller's events under a scoped key was ruled out. The hash
// chain covers the sealed bytes, so rewriting them makes every re-sealed event
// verify as tampered, and retention archives already hold copies of the old
// ciphertext that re-sealing cannot reach. Refusing the erasure outright was
// ruled out too: it leaves the data readable and unmarked, which is worse for
// the data subject, and two tenants sharing a legacy key would each be refused
// because of the other, forever.
//
// The check only sees live rows. If retention has already archived and deleted
// another scope's legacy events, destroying the key also makes that archive
// unreadable. A legacy key is only ever destroyed when the caller has live
// legacy events of its own, which keeps a scope that never used the key from
// destroying it.
func (s *Service) Erase(ctx context.Context, input *Input, appID, tenantID string) (*Result, error) {
	scope := Scope{AppID: appID, TenantID: tenantID}
	subject := SubjectQuery{Scope: scope, SubjectID: input.SubjectID}

	// 1. Count events for subject.
	count, err := s.store.CountBySubject(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("count subject events: %w", err)
	}

	// 2. Record the erasure before anything irreversible happens.
	erasureID := id.NewErasureID()
	rec := &Erasure{
		Entity:         chronicle.NewEntity(),
		ID:             erasureID,
		SubjectID:      input.SubjectID,
		Reason:         input.Reason,
		RequestedBy:    input.RequestedBy,
		EventsAffected: count,
		AppID:          appID,
		TenantID:       tenantID,
		Status:         StatusPending,
	}
	if err = s.store.RecordErasure(ctx, rec); err != nil {
		return nil, fmt.Errorf("record erasure: %w", err)
	}

	// 3. Mark events as erased.
	affected, err := s.store.MarkErased(ctx, subject, erasureID)
	if err != nil {
		return nil, fmt.Errorf("erasure %s: mark events: %w", erasureID, err)
	}

	// 4. Destroy the keys this scope's events were sealed under. Every key is
	// attempted even after a failure: the events are already marked, so each
	// key that goes is one fewer for the retry.
	usage, err := s.store.SubjectKeyUsage(ctx, input.SubjectID)
	if err != nil {
		return nil, fmt.Errorf("erasure %s: read key usage: %w", erasureID, err)
	}
	plan := planKeyDestruction(scope, input.SubjectID, usage)

	var delErrs []error
	for _, keyID := range plan.destroy {
		if delErr := s.keyStore.Delete(keyID); delErr != nil {
			delErrs = append(delErrs, delErr)
		}
	}
	if err = errors.Join(delErrs...); err != nil {
		return nil, fmt.Errorf("erasure %s: destroy keys: %w", erasureID, err)
	}

	// 5. Complete the record.
	outcome := Outcome{
		EventsAffected:    affected,
		KeyDestroyed:      !plan.legacyRetained,
		LegacyKeyRetained: plan.legacyRetained,
	}
	if err = s.store.CompleteErasure(ctx, erasureID, outcome); err != nil {
		return nil, fmt.Errorf("erasure %s: complete record: %w", erasureID, err)
	}

	return &Result{
		ID:                erasureID,
		SubjectID:         input.SubjectID,
		EventsAffected:    affected,
		KeyDestroyed:      outcome.KeyDestroyed,
		LegacyKeyRetained: outcome.LegacyKeyRetained,
	}, nil
}

// keyPlan is the set of keys an erasure may destroy.
type keyPlan struct {
	destroy        []string
	legacyRetained bool
}

// planKeyDestruction decides which keys an erasure in scope may destroy, given
// where the subject's events live and what they were sealed under.
//
// Scoped keys are derived from each covered row's own app and tenant, never
// taken from the row's EncryptionKeyID. That column is not covered by the hash,
// so trusting it would let an edited row name another scope's key for
// deletion. The caller's own scoped key is always included, so a key whose
// events retention has already removed still goes.
func planKeyDestruction(scope Scope, subjectID string, usage []KeyUsage) keyPlan {
	var plan keyPlan
	seen := make(map[string]bool)
	add := func(keyID string) {
		if !seen[keyID] {
			seen[keyID] = true
			plan.destroy = append(plan.destroy, keyID)
		}
	}

	add(crypto.ScopedKeyID(scope.AppID, scope.TenantID, subjectID))

	ownLegacy, sharedLegacy := false, false
	for _, u := range usage {
		covered := scope.covers(u.AppID, u.TenantID)
		if covered {
			add(crypto.ScopedKeyID(u.AppID, u.TenantID, subjectID))
		}

		if u.EncryptionKeyID == "" {
			continue // never sealed
		}
		if _, _, _, scoped := crypto.ParseScopedKeyID(u.EncryptionKeyID); scoped {
			continue
		}

		// Sealed under the legacy key, which is named by the subject ID.
		switch {
		case covered:
			ownLegacy = true
		case !u.Erased:
			sharedLegacy = true
		}
	}

	// A subject ID spelled like a scoped key ID would name some scope's current
	// key rather than a legacy one, so it is never deleted under the legacy
	// name. Nothing legitimate produces such a subject ID.
	_, _, _, subjectLooksScoped := crypto.ParseScopedKeyID(subjectID)

	if ownLegacy {
		if sharedLegacy || subjectLooksScoped {
			plan.legacyRetained = true
		} else {
			add(subjectID)
		}
	}
	return plan
}
