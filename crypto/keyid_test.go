package crypto_test

import (
	"errors"
	"testing"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/crypto"
)

// TestScopedKeyIDSeparatorsCannotCollide pins the reason the ID is
// length-prefixed. Each pair below names two different scopes that a bare join
// on ":" or "|" would render identically, and so would have shared one key.
func TestScopedKeyIDSeparatorsCannotCollide(t *testing.T) {
	type triple struct{ app, tenant, subject string }
	pairs := []struct {
		name string
		a, b triple
	}{
		{"colon between app and tenant", triple{"a:b", "c", "s"}, triple{"a", "b:c", "s"}},
		{"colon between tenant and subject", triple{"a", "b:c", "s"}, triple{"a", "b", "c:s"}},
		{"pipe between app and tenant", triple{"a|b", "c", "s"}, triple{"a", "b|c", "s"}},
		{"pipe between tenant and subject", triple{"a", "b|c", "s"}, triple{"a", "b", "c|s"}},
		{"length-shaped content", triple{"1:a", "", "s"}, triple{"", "1:a", "s"}},
		{"empty fields shift", triple{"", "a", "s"}, triple{"a", "", "s"}},
	}
	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			ka := crypto.ScopedKeyID(p.a.app, p.a.tenant, p.a.subject)
			kb := crypto.ScopedKeyID(p.b.app, p.b.tenant, p.b.subject)
			if ka == kb {
				t.Fatalf("%+v and %+v both map to %q", p.a, p.b, ka)
			}
		})
	}
}

func TestScopedKeyIDRoundTrips(t *testing.T) {
	cases := [][3]string{
		{"app-1", "tenant-a", "user-42"},
		{"", "", ""},
		{"a:b", "c|d", "3:xyz"},
		{"ck1|", "ünïcødé", "alice@example.com"},
	}
	for _, c := range cases {
		keyID := crypto.ScopedKeyID(c[0], c[1], c[2])
		app, tenant, subject, ok := crypto.ParseScopedKeyID(keyID)
		if !ok || app != c[0] || tenant != c[1] || subject != c[2] {
			t.Errorf("ParseScopedKeyID(%q) = %q, %q, %q, %v; want %q", keyID, app, tenant, subject, ok, c)
		}
	}
}

// TestParseScopedKeyIDRejectsLegacyAndMalformedIDs matters because a failed
// parse is how Open and erasure recognise a key sealed before scoping.
func TestParseScopedKeyIDRejectsLegacyAndMalformedIDs(t *testing.T) {
	for _, keyID := range []string{
		"",
		"user-42",
		"alice@example.com",
		"ck1|",
		"ck1|3:abc|0:",             // missing the subject
		"ck1|3:abc|0:|0:|",         // trailing separator
		"ck1|3:abc|0:|0:x",         // trailing bytes
		"ck1|03:abc|0:|0:",         // non-canonical length
		"ck1|+3:abc|0:|0:",         // non-canonical length
		"ck1|9:abc|0:|0:",          // length overruns
		"ck1|-1:|0:|0:",            // negative length
		"ck2|3:abc|0:|0:",          // unknown version
		"ck1|3:abc0:|0:",           // missing separator
		"CK1|3:abc|0:|0:",          // prefix is case-sensitive
		"ck1|3:abc|1:t|7:user-42 ", // trailing space
	} {
		if _, _, _, ok := crypto.ParseScopedKeyID(keyID); ok {
			t.Errorf("ParseScopedKeyID(%q) accepted a string ScopedKeyID cannot produce", keyID)
		}
	}
}

func TestSealKeysEachScopeSeparately(t *testing.T) {
	sealer := crypto.NewSealer(crypto.NewInMemoryKeyStore())

	a := sealableEvent()
	a.AppID, a.TenantID = "a:b", "c"
	b := sealableEvent()
	b.AppID, b.TenantID = "a", "b:c"

	if err := sealer.Seal(a); err != nil {
		t.Fatalf("Seal a: %v", err)
	}
	if err := sealer.Seal(b); err != nil {
		t.Fatalf("Seal b: %v", err)
	}

	if a.EncryptionKeyID != crypto.ScopedKeyID("a:b", "c", a.SubjectID) {
		t.Errorf("EncryptionKeyID = %q, want the scoped ID", a.EncryptionKeyID)
	}
	if a.EncryptionKeyID == b.EncryptionKeyID {
		t.Fatalf("colliding scopes sealed under the same key %q", a.EncryptionKeyID)
	}
}

// TestOpenReadsLegacySealedEvents covers every event written before keys were
// scoped: sealed under a key named by the bare subject ID.
func TestOpenReadsLegacySealedEvents(t *testing.T) {
	for _, recorded := range []string{
		"subject-9", // what InMemoryKeyStore used to return
		"kms-gen-7", // a custom store returning its own ID; Open never used it
	} {
		t.Run(recorded, func(t *testing.T) {
			keys := crypto.NewInMemoryKeyStore()
			event := sealLegacy(t, keys, recorded)

			if err := crypto.NewSealer(keys).Open(event); err != nil {
				t.Fatalf("Open: %v", err)
			}
			if event.Reason != "subject access request" || event.Metadata["email"] != "alice@example.com" {
				t.Errorf("legacy event opened to Reason=%q Metadata=%v", event.Reason, event.Metadata)
			}
		})
	}
}

// sealLegacy produces an event exactly as the pre-scoping Sealer left it: its
// payload sealed with the key stored under the subject ID, and recordedKeyID
// in EncryptionKeyID.
func sealLegacy(t *testing.T, keys crypto.KeyStore, recordedKeyID string) *audit.Event {
	t.Helper()
	event := sealableEvent()
	if err := crypto.NewSealer(subjectKeyed{keys}).Seal(event); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	event.EncryptionKeyID = recordedKeyID
	return event
}

// subjectKeyed addresses the underlying store by subject ID alone, the way the
// Sealer did before keys were scoped.
type subjectKeyed struct{ inner crypto.KeyStore }

func (s subjectKeyed) GetOrCreate(keyID string) ([]byte, string, error) {
	return s.inner.GetOrCreate(subjectOf(keyID))
}
func (s subjectKeyed) Get(keyID string) ([]byte, error) { return s.inner.Get(subjectOf(keyID)) }
func (s subjectKeyed) Delete(keyID string) error        { return s.inner.Delete(subjectOf(keyID)) }

func subjectOf(keyID string) string {
	if _, _, subject, ok := crypto.ParseScopedKeyID(keyID); ok {
		return subject
	}
	return keyID
}

// TestOpenRefusesAKeyIDNamingAnotherScope guards the unhashed EncryptionKeyID
// column: an edited row must not be able to point a read at another scope.
func TestOpenRefusesAKeyIDNamingAnotherScope(t *testing.T) {
	keys := crypto.NewInMemoryKeyStore()
	sealer := crypto.NewSealer(keys)

	event := sealableEvent()
	if err := sealer.Seal(event); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	event.EncryptionKeyID = crypto.ScopedKeyID("app-2", event.TenantID, event.SubjectID)

	if err := sealer.Open(event); !errors.Is(err, crypto.ErrKeyScopeMismatch) {
		t.Fatalf("Open = %v, want ErrKeyScopeMismatch", err)
	}
}

// TestOpenRedactsAnErasedEventWhoseKeySurvives covers a legacy key retained
// because another scope still depends on it. The event is flagged erased, so
// it must not display its payload even though it could be decrypted.
func TestOpenRedactsAnErasedEventWhoseKeySurvives(t *testing.T) {
	sealer := crypto.NewSealer(crypto.NewInMemoryKeyStore())

	event := sealableEvent()
	if err := sealer.Seal(event); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	event.Erased = true

	if err := sealer.Open(event); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if event.Reason != crypto.ErasedMarker || event.IP != crypto.ErasedMarker || event.Metadata != nil {
		t.Errorf("erased event opened to Reason=%q IP=%q Metadata=%v", event.Reason, event.IP, event.Metadata)
	}
}
