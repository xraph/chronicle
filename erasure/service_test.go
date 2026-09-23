package erasure_test

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/crypto"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/store/memory"
)

// fixture is a memory store, a key store and the sealer and erasure service
// sharing them, the same wiring the extension builds.
type fixture struct {
	store  *memory.Store
	keys   *crypto.InMemoryKeyStore
	sealer *crypto.Sealer
	svc    *erasure.Service
}

func newFixture() *fixture {
	st := memory.New()
	keys := crypto.NewInMemoryKeyStore()
	return &fixture{
		store:  st,
		keys:   keys,
		sealer: crypto.NewSealer(keys),
		svc:    erasure.NewService(st, keys),
	}
}

func subjectEvent(appID, tenantID, subjectID, reason string) *audit.Event {
	return &audit.Event{
		ID:        id.NewAuditID(),
		StreamID:  id.NewStreamID(),
		Sequence:  1,
		AppID:     appID,
		TenantID:  tenantID,
		UserID:    "operator@corp",
		IP:        "203.0.113.10",
		Action:    "export",
		Resource:  "user",
		Category:  "data",
		Outcome:   audit.OutcomeSuccess,
		Severity:  audit.SeverityInfo,
		Reason:    reason,
		SubjectID: subjectID,
		Metadata:  map[string]any{"email": "someone@example.com"},
		Timestamp: time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC),
	}
}

// record seals an event the way Chronicle.Record does and stores it.
func (f *fixture) record(t *testing.T, e *audit.Event) *audit.Event {
	t.Helper()
	if err := f.sealer.Seal(e); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := f.store.Append(context.Background(), e); err != nil {
		t.Fatalf("Append: %v", err)
	}
	return e
}

// recordLegacy stores an event sealed the way Chronicle did before keys were
// scoped: under the bare subject ID, with that ID recorded as the key.
func (f *fixture) recordLegacy(t *testing.T, e *audit.Event) *audit.Event {
	t.Helper()
	return f.recordLegacyAs(t, e, e.SubjectID)
}

// recordLegacyAs is recordLegacy for a custom key store that returned its own
// key ID from GetOrCreate. The old Sealer recorded that ID but always looked
// the key up by subject.
func (f *fixture) recordLegacyAs(t *testing.T, e *audit.Event, recordedKeyID string) *audit.Event {
	t.Helper()
	legacy := crypto.NewSealer(legacyKeyStore{f.keys})
	if err := legacy.Seal(e); err != nil {
		t.Fatalf("legacy Seal: %v", err)
	}
	e.EncryptionKeyID = recordedKeyID
	if err := f.store.Append(context.Background(), e); err != nil {
		t.Fatalf("Append: %v", err)
	}
	return e
}

// legacyKeyStore rewrites every key ID to the subject it names, which is how
// the key store was addressed before this fix. It lets a test seal an event
// under exactly the key an old deployment would hold.
type legacyKeyStore struct{ inner crypto.KeyStore }

func (l legacyKeyStore) GetOrCreate(keyID string) ([]byte, string, error) {
	return l.inner.GetOrCreate(subjectOf(keyID))
}
func (l legacyKeyStore) Get(keyID string) ([]byte, error) { return l.inner.Get(subjectOf(keyID)) }
func (l legacyKeyStore) Delete(keyID string) error        { return l.inner.Delete(subjectOf(keyID)) }

func subjectOf(keyID string) string {
	if _, _, subject, ok := crypto.ParseScopedKeyID(keyID); ok {
		return subject
	}
	return keyID
}

// open reads an event back from the store and decrypts a copy of it, which is
// what every display read path does.
func (f *fixture) open(t *testing.T, eventID id.ID) *audit.Event {
	t.Helper()
	stored, err := f.store.Get(context.Background(), eventID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	clone := *stored
	if err := f.sealer.Open(&clone); err != nil {
		t.Fatalf("Open: %v", err)
	}
	return &clone
}

func (f *fixture) erase(t *testing.T, subjectID, appID, tenantID string) *erasure.Result {
	t.Helper()
	res, err := f.svc.Erase(context.Background(), &erasure.Input{
		SubjectID:   subjectID,
		Reason:      "GDPR Article 17",
		RequestedBy: "dpo@" + appID,
	}, appID, tenantID)
	if err != nil {
		t.Fatalf("Erase: %v", err)
	}
	return res
}

// TestEraseDoesNotReachAnotherApp is the reported probe. Two apps hold events
// for the same subject ID. Erasing it in one of them used to destroy the one key
// both shared, so the other app's event read back as "[ERASED]" with no erasure
// record in its own scope to say why.
func TestEraseDoesNotReachAnotherApp(t *testing.T) {
	f := newFixture()
	ctx := context.Background()

	mine := f.record(t, subjectEvent("app-1", "tenant-a", "user-42", "mine"))
	theirs := f.record(t, subjectEvent("app-2", "tenant-b", "user-42", "theirs"))

	if mine.EncryptionKeyID == theirs.EncryptionKeyID {
		t.Fatalf("both scopes sealed under key %q", mine.EncryptionKeyID)
	}

	res := f.erase(t, "user-42", "app-1", "tenant-a")
	if res.EventsAffected != 1 || !res.KeyDestroyed {
		t.Fatalf("erase result = %+v, want 1 event and key destroyed", res)
	}

	got := f.open(t, theirs.ID)
	if got.Reason != "theirs" || got.Erased {
		t.Errorf("app-2 event after app-1 erasure: Reason=%q Erased=%v, want %q and false",
			got.Reason, got.Erased, "theirs")
	}
	if got.Metadata["email"] != "someone@example.com" {
		t.Errorf("app-2 metadata after app-1 erasure = %v", got.Metadata)
	}
	if _, err := f.keys.Get(theirs.EncryptionKeyID); err != nil {
		t.Errorf("app-2 key after app-1 erasure: %v", err)
	}

	n, err := f.store.CountErasures(ctx, erasure.Scope{AppID: "app-2", TenantID: "tenant-b"})
	if err != nil || n != 0 {
		t.Errorf("app-2 erasure records = %d, %v; want 0", n, err)
	}

	// The erasing scope's own data is gone for good.
	if got := f.open(t, mine.ID); got.Reason != crypto.ErasedMarker || !got.Erased {
		t.Errorf("app-1 event after its erasure: Reason=%q Erased=%v", got.Reason, got.Erased)
	}
	if _, err := f.keys.Get(mine.EncryptionKeyID); err == nil {
		t.Error("app-1 key survived its own erasure")
	}
}

// TestEraseKeepsCollidingScopesApart erases in app "a:b" / tenant "c" and
// checks app "a" / tenant "b:c" is untouched. A key ID built by joining on ":"
// would give both scopes the same key.
func TestEraseKeepsCollidingScopesApart(t *testing.T) {
	f := newFixture()

	mine := f.record(t, subjectEvent("a:b", "c", "user-42", "mine"))
	theirs := f.record(t, subjectEvent("a", "b:c", "user-42", "theirs"))
	if mine.EncryptionKeyID == theirs.EncryptionKeyID {
		t.Fatalf("colliding scopes share key %q", mine.EncryptionKeyID)
	}

	f.erase(t, "user-42", "a:b", "c")

	if got := f.open(t, theirs.ID); got.Reason != "theirs" || got.Erased {
		t.Errorf("a / b:c event after erasing a:b / c: Reason=%q Erased=%v", got.Reason, got.Erased)
	}
	if got := f.open(t, mine.ID); got.Reason != crypto.ErasedMarker {
		t.Errorf("a:b / c event after its erasure: Reason=%q", got.Reason)
	}
}

// TestAppWideEraseDestroysEveryTenantsKeyInTheApp checks key destruction
// reaches exactly as far as MarkErased. An empty tenant covers every tenant in
// the app, so every one of those tenants' keys has to go, and nothing outside
// the app.
func TestAppWideEraseDestroysEveryTenantsKeyInTheApp(t *testing.T) {
	f := newFixture()

	t1 := f.record(t, subjectEvent("app-1", "tenant-a", "user-42", "t1"))
	t2 := f.record(t, subjectEvent("app-1", "tenant-b", "user-42", "t2"))
	other := f.record(t, subjectEvent("app-2", "tenant-a", "user-42", "other"))

	res := f.erase(t, "user-42", "app-1", "")
	if res.EventsAffected != 2 || !res.KeyDestroyed {
		t.Fatalf("erase result = %+v, want 2 events and key destroyed", res)
	}

	for _, e := range []*audit.Event{t1, t2} {
		if _, err := f.keys.Get(e.EncryptionKeyID); err == nil {
			t.Errorf("key %q survived an app-wide erasure", e.EncryptionKeyID)
		}
		if got := f.open(t, e.ID); got.Reason != crypto.ErasedMarker {
			t.Errorf("%s/%s event Reason=%q after app-wide erasure", e.AppID, e.TenantID, got.Reason)
		}
	}
	if got := f.open(t, other.ID); got.Reason != "other" || got.Erased {
		t.Errorf("app-2 event after app-1 erasure: Reason=%q Erased=%v", got.Reason, got.Erased)
	}
}

// TestEraseDestroysAnUnsharedLegacyKey is the single-tenant upgrade: every
// event predates scoping, and only this scope ever used the subject's key.
func TestEraseDestroysAnUnsharedLegacyKey(t *testing.T) {
	f := newFixture()

	old := f.recordLegacy(t, subjectEvent("app-1", "tenant-a", "user-42", "old"))
	if got := f.open(t, old.ID); got.Reason != "old" {
		t.Fatalf("legacy event before erasure: Reason=%q", got.Reason)
	}
	fresh := f.record(t, subjectEvent("app-1", "tenant-a", "user-42", "fresh"))

	res := f.erase(t, "user-42", "app-1", "tenant-a")
	if !res.KeyDestroyed || res.LegacyKeyRetained || res.EventsAffected != 2 {
		t.Fatalf("erase result = %+v, want both keys destroyed", res)
	}
	if _, err := f.keys.Get("user-42"); err == nil {
		t.Error("the unshared legacy key survived erasure")
	}
	if _, err := f.keys.Get(fresh.EncryptionKeyID); err == nil {
		t.Error("the scoped key survived erasure")
	}
	for _, e := range []*audit.Event{old, fresh} {
		if got := f.open(t, e.ID); got.Reason != crypto.ErasedMarker {
			t.Errorf("event %q after erasure: Reason=%q", e.Reason, got.Reason)
		}
	}
}

// TestEraseRetainsASharedLegacyKey is the migration case the bug report
// describes. Two tenants' events for "user-42" were sealed under one legacy
// key before the upgrade. Erasing in one tenant must not destroy the other's
// data, so the key is kept, the erasing tenant's events are marked erased and
// redacted, and the result says the key was retained. When the other tenant
// later erases too, nobody depends on the key any more and it goes.
func TestEraseRetainsASharedLegacyKey(t *testing.T) {
	f := newFixture()
	ctx := context.Background()

	mineOld := f.recordLegacy(t, subjectEvent("app-1", "tenant-a", "user-42", "mine-old"))
	mineNew := f.record(t, subjectEvent("app-1", "tenant-a", "user-42", "mine-new"))
	theirs := f.recordLegacy(t, subjectEvent("app-2", "tenant-b", "user-42", "theirs"))

	res := f.erase(t, "user-42", "app-1", "tenant-a")
	if !res.LegacyKeyRetained || res.KeyDestroyed || res.EventsAffected != 2 {
		t.Fatalf("erase result = %+v, want legacy key retained and KeyDestroyed false", res)
	}

	rec, err := f.store.GetErasure(ctx, res.ID)
	if err != nil {
		t.Fatalf("GetErasure: %v", err)
	}
	if rec.KeyDestroyed {
		t.Error("erasure record claims the key was destroyed while it was retained")
	}

	// The other tenant's data is intact.
	if _, err := f.keys.Get("user-42"); err != nil {
		t.Fatalf("shared legacy key destroyed: %v", err)
	}
	if got := f.open(t, theirs.ID); got.Reason != "theirs" || got.Erased {
		t.Errorf("app-2 legacy event after app-1 erasure: Reason=%q Erased=%v", got.Reason, got.Erased)
	}

	// The erasing tenant's scoped key is gone, and its legacy event no longer
	// reads back even though its key survives.
	if _, err := f.keys.Get(mineNew.EncryptionKeyID); err == nil {
		t.Error("app-1's scoped key survived its erasure")
	}
	for _, e := range []*audit.Event{mineOld, mineNew} {
		if got := f.open(t, e.ID); got.Reason != crypto.ErasedMarker || !got.Erased {
			t.Errorf("app-1 event %q after erasure: Reason=%q Erased=%v", e.Reason, got.Reason, got.Erased)
		}
	}

	// Now the other tenant erases the same subject ID. Every other holder of
	// the legacy key is already erased, so this time it is destroyed.
	res = f.erase(t, "user-42", "app-2", "tenant-b")
	if res.LegacyKeyRetained || !res.KeyDestroyed {
		t.Fatalf("second erase result = %+v, want the legacy key destroyed", res)
	}
	if _, err := f.keys.Get("user-42"); err == nil {
		t.Error("legacy key survived once every scope using it had erased")
	}
}

// TestEraseLeavesALegacyKeyItNeverUsed covers a tenant that only started
// recording the subject after the upgrade. It has no claim on the legacy key,
// so its erasure must neither destroy it nor report it as retained.
func TestEraseLeavesALegacyKeyItNeverUsed(t *testing.T) {
	f := newFixture()

	mine := f.record(t, subjectEvent("app-1", "tenant-a", "user-42", "mine"))
	theirs := f.recordLegacy(t, subjectEvent("app-2", "tenant-b", "user-42", "theirs"))

	res := f.erase(t, "user-42", "app-1", "tenant-a")
	if !res.KeyDestroyed || res.LegacyKeyRetained {
		t.Fatalf("erase result = %+v, want scoped key destroyed and nothing retained", res)
	}
	if _, err := f.keys.Get(mine.EncryptionKeyID); err == nil {
		t.Error("app-1's scoped key survived its erasure")
	}
	if got := f.open(t, theirs.ID); got.Reason != "theirs" {
		t.Errorf("app-2 legacy event after app-1 erasure: Reason=%q", got.Reason)
	}
}

// TestEraseNeverDeletesAScopedKeyThroughTheLegacyName covers a subject ID
// spelled like another scope's key ID. The legacy key is named by the subject
// ID, so deleting "the legacy key" for that subject would delete the other
// scope's current key.
func TestEraseNeverDeletesAScopedKeyThroughTheLegacyName(t *testing.T) {
	f := newFixture()

	victim := f.record(t, subjectEvent("app-2", "tenant-b", "user-42", "victim"))
	lookalike := victim.EncryptionKeyID

	// A pre-upgrade event in app-1 whose subject ID is that key ID, recorded
	// by a custom key store that returned its own (non-scoped) key ID.
	f.recordLegacyAs(t, subjectEvent("app-1", "tenant-a", lookalike, "planted"), "kms-gen-1")

	res := f.erase(t, lookalike, "app-1", "tenant-a")
	if res.KeyDestroyed {
		t.Errorf("erase result = %+v, want KeyDestroyed false", res)
	}
	if _, err := f.keys.Get(victim.EncryptionKeyID); err != nil {
		t.Fatalf("app-2's key was deleted through the legacy name: %v", err)
	}
	if got := f.open(t, victim.ID); got.Reason != "victim" {
		t.Errorf("app-2 event after app-1 erasure: Reason=%q", got.Reason)
	}
}
