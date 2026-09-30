package erasure_test

import (
	"context"
	"errors"
	"testing"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/crypto"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/store/memory"
)

var (
	errRecord   = errors.New("record erasure: connection reset")
	errMark     = errors.New("mark erased: context canceled")
	errDelete   = errors.New("delete key: kms unavailable")
	errComplete = errors.New("complete erasure: deadline exceeded")
)

// flakyStore is a memory store whose writes can be made to fail.
type flakyStore struct {
	*memory.Store

	recordErr   error
	markErr     error
	completeErr error
}

func (s *flakyStore) RecordErasure(ctx context.Context, e *erasure.Erasure) error {
	if s.recordErr != nil {
		return s.recordErr
	}
	return s.Store.RecordErasure(ctx, e)
}

func (s *flakyStore) MarkErased(ctx context.Context, q erasure.SubjectQuery, erasureID id.ID) (int64, error) {
	if s.markErr != nil {
		return 0, s.markErr
	}
	return s.Store.MarkErased(ctx, q, erasureID)
}

func (s *flakyStore) CompleteErasure(ctx context.Context, erasureID id.ID, o erasure.Outcome) error {
	if s.completeErr != nil {
		return s.completeErr
	}
	return s.Store.CompleteErasure(ctx, erasureID, o)
}

// flakyKeyStore fails to delete the key IDs in fail and passes everything else
// through.
type flakyKeyStore struct {
	crypto.KeyStore

	fail map[string]bool
}

func (k *flakyKeyStore) Delete(keyID string) error {
	if k.fail[keyID] {
		return errDelete
	}
	return k.KeyStore.Delete(keyID)
}

// eraseInput is the request every test here makes, from app-1's DPO.
func eraseInput() *erasure.Input {
	return &erasure.Input{
		SubjectID:   "user-42",
		Reason:      "GDPR Article 17",
		RequestedBy: "dpo@app-1",
	}
}

// records returns every erasure record in app-1 and the given tenant.
func (f *fixture) records(t *testing.T, tenantID string) []*erasure.Erasure {
	t.Helper()
	recs, err := f.store.ListErasures(context.Background(), erasure.ListOpts{
		Scope: erasure.Scope{AppID: "app-1", TenantID: tenantID},
	})
	if err != nil {
		t.Fatalf("ListErasures: %v", err)
	}
	return recs
}

// assertPending checks a record says the erasure did not finish and claims no
// key was destroyed.
func assertPending(t *testing.T, rec *erasure.Erasure) {
	t.Helper()
	if rec.Status != erasure.StatusPending || rec.KeyDestroyed || rec.LegacyKeyRetained {
		t.Errorf("record Status=%q KeyDestroyed=%v LegacyKeyRetained=%v, want pending and nothing destroyed",
			rec.Status, rec.KeyDestroyed, rec.LegacyKeyRetained)
	}
}

// assertCompleted checks the record behind a successful erasure.
func (f *fixture) assertCompleted(t *testing.T, res *erasure.Result) {
	t.Helper()
	rec, err := f.store.GetErasure(context.Background(), res.ID)
	if err != nil {
		t.Fatalf("GetErasure: %v", err)
	}
	if rec.Status != erasure.StatusCompleted || rec.KeyDestroyed != res.KeyDestroyed ||
		rec.LegacyKeyRetained != res.LegacyKeyRetained || rec.EventsAffected != res.EventsAffected {
		t.Errorf("record = %+v, want completed and matching result %+v", rec, res)
	}
}

// assertIntact checks an event still reads back in full and is not marked.
func (f *fixture) assertIntact(t *testing.T, e *audit.Event, want string) {
	t.Helper()
	got := f.open(t, e.ID)
	if got.Reason != want || got.Erased {
		t.Errorf("event %q: Reason=%q Erased=%v, want %q and not erased", want, got.Reason, got.Erased, want)
	}
}

// assertErased checks an event is marked and redacted.
func (f *fixture) assertErased(t *testing.T, e *audit.Event) {
	t.Helper()
	got := f.open(t, e.ID)
	if got.Reason != crypto.ErasedMarker || !got.Erased {
		t.Errorf("event %q: Reason=%q Erased=%v, want erased", e.Reason, got.Reason, got.Erased)
	}
}

func (f *fixture) assertKeyAlive(t *testing.T, keyID string) {
	t.Helper()
	if _, err := f.keys.Get(keyID); err != nil {
		t.Errorf("key %q was destroyed: %v", keyID, err)
	}
}

func (f *fixture) assertKeyGone(t *testing.T, keyID string) {
	t.Helper()
	if _, err := f.keys.Get(keyID); err == nil {
		t.Errorf("key %q survived", keyID)
	}
}

// TestEraseRecordFailureDestroysNothing: when the erasure cannot be recorded,
// nothing else may happen. There is no audit trail to explain a destroyed key.
func TestEraseRecordFailureDestroysNothing(t *testing.T) {
	f := newFixture()
	ev := f.record(t, subjectEvent("app-1", "tenant-a", "user-42", "mine"))

	st := &flakyStore{Store: f.store, recordErr: errRecord}
	_, err := erasure.NewService(st, f.keys).Erase(context.Background(), eraseInput(), "app-1", "tenant-a")
	if !errors.Is(err, errRecord) {
		t.Fatalf("Erase error = %v, want %v", err, errRecord)
	}

	if recs := f.records(t, "tenant-a"); len(recs) != 0 {
		t.Errorf("erasure records = %d, want 0", len(recs))
	}
	f.assertIntact(t, ev, "mine")
	f.assertKeyAlive(t, ev.EncryptionKeyID)
}

// TestEraseMarkFailureKeepsTheKey: the record is written, then marking fails.
// The key must survive, because the record says it was not destroyed and the
// events are still unmarked. A retry then completes the erasure.
func TestEraseMarkFailureKeepsTheKey(t *testing.T) {
	f := newFixture()
	ctx := context.Background()
	ev := f.record(t, subjectEvent("app-1", "tenant-a", "user-42", "mine"))

	st := &flakyStore{Store: f.store, markErr: errMark}
	svc := erasure.NewService(st, f.keys)
	if _, err := svc.Erase(ctx, eraseInput(), "app-1", "tenant-a"); !errors.Is(err, errMark) {
		t.Fatalf("Erase error = %v, want %v", err, errMark)
	}

	recs := f.records(t, "tenant-a")
	if len(recs) != 1 {
		t.Fatalf("erasure records = %d, want 1", len(recs))
	}
	failed := recs[0]
	assertPending(t, failed)
	if failed.RequestedBy != "dpo@app-1" || failed.Reason != "GDPR Article 17" {
		t.Errorf("record = %+v, want who and why", failed)
	}
	f.assertIntact(t, ev, "mine")
	f.assertKeyAlive(t, ev.EncryptionKeyID)

	// The store recovers and the operator retries.
	st.markErr = nil
	res, err := svc.Erase(ctx, eraseInput(), "app-1", "tenant-a")
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !res.KeyDestroyed || res.EventsAffected != 1 {
		t.Fatalf("retry result = %+v, want 1 event and key destroyed", res)
	}
	f.assertErased(t, ev)
	f.assertKeyGone(t, ev.EncryptionKeyID)
	f.assertCompleted(t, res)

	// The failed attempt stays on record, still pending.
	if rec, err := f.store.GetErasure(ctx, failed.ID); err != nil {
		t.Fatalf("GetErasure(failed): %v", err)
	} else {
		assertPending(t, rec)
	}
	if got := f.open(t, ev.ID); got.ErasureID != res.ID.String() {
		t.Errorf("event ErasureID = %q, want the retry's %q", got.ErasureID, res.ID)
	}
}

// TestEraseKeyDeleteFailureIsReported: the events are marked but the key
// store refuses to delete the key. The caller must get an error and the record
// must say the key was not destroyed, so an operator knows to retry.
func TestEraseKeyDeleteFailureIsReported(t *testing.T) {
	f := newFixture()
	ctx := context.Background()
	ev := f.record(t, subjectEvent("app-1", "tenant-a", "user-42", "mine"))

	keys := &flakyKeyStore{KeyStore: f.keys, fail: map[string]bool{ev.EncryptionKeyID: true}}
	svc := erasure.NewService(f.store, keys)
	if _, err := svc.Erase(ctx, eraseInput(), "app-1", "tenant-a"); !errors.Is(err, errDelete) {
		t.Fatalf("Erase error = %v, want %v", err, errDelete)
	}

	recs := f.records(t, "tenant-a")
	if len(recs) != 1 {
		t.Fatalf("erasure records = %d, want 1", len(recs))
	}
	assertPending(t, recs[0])
	f.assertErased(t, ev)
	f.assertKeyAlive(t, ev.EncryptionKeyID)

	// The key store recovers and the operator retries.
	keys.fail = nil
	res, err := svc.Erase(ctx, eraseInput(), "app-1", "tenant-a")
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !res.KeyDestroyed || res.EventsAffected != 1 {
		t.Fatalf("retry result = %+v, want 1 event and key destroyed", res)
	}
	f.assertKeyGone(t, ev.EncryptionKeyID)
	f.assertCompleted(t, res)
	if got := f.open(t, ev.ID); got.ErasureID != res.ID.String() {
		t.Errorf("event ErasureID = %q, want the retry's %q", got.ErasureID, res.ID)
	}
}

// TestErasePartialKeyDeleteFailure: an app-wide erasure destroys one key per
// tenant. One delete fails. The record must not say destroyed, even though the
// other tenant's key is gone, and the retry finishes the job.
func TestErasePartialKeyDeleteFailure(t *testing.T) {
	f := newFixture()
	ctx := context.Background()
	t1 := f.record(t, subjectEvent("app-1", "tenant-a", "user-42", "t1"))
	t2 := f.record(t, subjectEvent("app-1", "tenant-b", "user-42", "t2"))

	keys := &flakyKeyStore{KeyStore: f.keys, fail: map[string]bool{t2.EncryptionKeyID: true}}
	svc := erasure.NewService(f.store, keys)
	if _, err := svc.Erase(ctx, eraseInput(), "app-1", ""); !errors.Is(err, errDelete) {
		t.Fatalf("Erase error = %v, want %v", err, errDelete)
	}

	recs := f.records(t, "")
	if len(recs) != 1 {
		t.Fatalf("erasure records = %d, want 1", len(recs))
	}
	assertPending(t, recs[0])
	f.assertKeyAlive(t, t2.EncryptionKeyID)

	keys.fail = nil
	res, err := svc.Erase(ctx, eraseInput(), "app-1", "")
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !res.KeyDestroyed || res.EventsAffected != 2 {
		t.Fatalf("retry result = %+v, want 2 events and keys destroyed", res)
	}
	f.assertKeyGone(t, t1.EncryptionKeyID)
	f.assertKeyGone(t, t2.EncryptionKeyID)
	f.assertCompleted(t, res)
}

// TestEraseLegacyKeyDeleteFailure: an unshared legacy key fails to delete. The
// record must not say the key was destroyed or retained, and the retry
// destroys it.
func TestEraseLegacyKeyDeleteFailure(t *testing.T) {
	f := newFixture()
	ctx := context.Background()
	old := f.recordLegacy(t, subjectEvent("app-1", "tenant-a", "user-42", "old"))

	keys := &flakyKeyStore{KeyStore: f.keys, fail: map[string]bool{"user-42": true}}
	svc := erasure.NewService(f.store, keys)
	if _, err := svc.Erase(ctx, eraseInput(), "app-1", "tenant-a"); !errors.Is(err, errDelete) {
		t.Fatalf("Erase error = %v, want %v", err, errDelete)
	}
	recs := f.records(t, "tenant-a")
	if len(recs) != 1 {
		t.Fatalf("erasure records = %d, want 1", len(recs))
	}
	assertPending(t, recs[0])
	f.assertKeyAlive(t, "user-42")
	f.assertErased(t, old)

	keys.fail = nil
	res, err := svc.Erase(ctx, eraseInput(), "app-1", "tenant-a")
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !res.KeyDestroyed || res.LegacyKeyRetained {
		t.Fatalf("retry result = %+v, want the legacy key destroyed", res)
	}
	f.assertKeyGone(t, "user-42")
	f.assertCompleted(t, res)
}

// TestEraseCompleteFailureIsReported: everything is done except writing the
// outcome. The caller must hear about it, and the record must not claim more
// than it knows: it stays pending. A retry completes a fresh record.
func TestEraseCompleteFailureIsReported(t *testing.T) {
	f := newFixture()
	ctx := context.Background()
	ev := f.record(t, subjectEvent("app-1", "tenant-a", "user-42", "mine"))

	st := &flakyStore{Store: f.store, completeErr: errComplete}
	svc := erasure.NewService(st, f.keys)
	if _, err := svc.Erase(ctx, eraseInput(), "app-1", "tenant-a"); !errors.Is(err, errComplete) {
		t.Fatalf("Erase error = %v, want %v", err, errComplete)
	}
	recs := f.records(t, "tenant-a")
	if len(recs) != 1 {
		t.Fatalf("erasure records = %d, want 1", len(recs))
	}
	assertPending(t, recs[0])
	f.assertErased(t, ev)

	st.completeErr = nil
	res, err := svc.Erase(ctx, eraseInput(), "app-1", "tenant-a")
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !res.KeyDestroyed || res.EventsAffected != 1 {
		t.Fatalf("retry result = %+v, want 1 event and key destroyed", res)
	}
	f.assertCompleted(t, res)
}
