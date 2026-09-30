package contract

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	dashauth "github.com/xraph/forge/extensions/dashboard/auth"
	fcontract "github.com/xraph/forge/extensions/dashboard/contract"
	"github.com/xraph/forge/extensions/dashboard/contract/loader"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/crypto"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/sealedstore"
)

// ──────────────────────────────────────────────────
// Test doubles and helpers for erasures.request
// ──────────────────────────────────────────────────

// erasureRequestSpyStore is the store an erasure.Service runs over when a test
// wants to see exactly what Erase asked of it: which scope it counted and
// marked in, and what it recorded, without any real events behind it.
type erasureRequestSpyStore struct {
	stubStore

	count     int64
	affected  int64
	usage     []erasure.KeyUsage
	recordErr error

	counted  []erasure.SubjectQuery
	marked   []erasure.SubjectQuery
	recorded []*erasure.Erasure
}

func (s *erasureRequestSpyStore) CountBySubject(_ context.Context, q erasure.SubjectQuery) (int64, error) {
	s.counted = append(s.counted, q)
	return s.count, nil
}

func (s *erasureRequestSpyStore) SubjectKeyUsage(context.Context, string) ([]erasure.KeyUsage, error) {
	return s.usage, nil
}

func (s *erasureRequestSpyStore) RecordErasure(_ context.Context, e *erasure.Erasure) error {
	s.recorded = append(s.recorded, e)
	return s.recordErr
}

func (s *erasureRequestSpyStore) MarkErased(_ context.Context, q erasure.SubjectQuery, _ id.ID) (int64, error) {
	s.marked = append(s.marked, q)
	return s.affected, nil
}

// touched reports whether Erase reached the store at all.
func (s *erasureRequestSpyStore) touched() bool {
	return len(s.counted)+len(s.marked)+len(s.recorded) > 0
}

// deps is Deps with a real erasure.Service over the spy and an in-memory key
// store.
func (s *erasureRequestSpyStore) deps() Deps {
	return Deps{Store: s, Erasure: erasure.NewService(s, crypto.NewInMemoryKeyStore())}
}

// erasureAdmin is a principal whose subject is not the stub default, so a
// test can tell "taken from the principal" from a value it happened to share.
func erasureAdmin(claims map[string]any) fcontract.Principal {
	return fcontract.Principal{
		User:   &dashauth.UserInfo{Subject: "dpo-9", Claims: claims, Scopes: []string{appWideScope}},
		Claims: claims,
	}
}

func erasureRequestIn(subject, reason string) RequestErasureInput {
	return RequestErasureInput{SubjectID: subject, Reason: reason}
}

// ──────────────────────────────────────────────────
// Manifest
// ──────────────────────────────────────────────────

func erasureRequestIntent(t *testing.T) fcontract.Intent {
	t.Helper()
	m, err := loader.Load(bytes.NewReader(manifestYAML), "manifest.yaml")
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	for _, in := range m.Intents {
		if in.Name == "erasures.request" {
			return in
		}
	}
	t.Fatal("erasures.request is not in the manifest")
	return fcontract.Intent{}
}

// The command destroys keys, so it is the admin scope or nothing. Loading the
// manifest and evaluating the predicate proves the yaml key is one the loader
// reads: a misspelt key loads as an empty predicate that allows everyone, and
// the write scope alone must not be enough.
func TestErasureRequestRequiresTheAdminScope(t *testing.T) {
	in := erasureRequestIntent(t)
	if in.Kind != fcontract.IntentKindCommand || in.Capability != fcontract.CapWrite {
		t.Errorf("kind %s capability %s, want command/write", in.Kind, in.Capability)
	}

	user := func(scopes ...string) *dashauth.UserInfo {
		return &dashauth.UserInfo{Subject: "operator-1", Scopes: scopes}
	}
	p := in.Requires
	if !p.Allow(user("chronicle.admin"), nil) {
		t.Error("refuses a principal with chronicle.admin")
	}
	for name, u := range map[string]*dashauth.UserInfo{
		"write only":      user("chronicle.write"),
		"read only":       user("chronicle.read"),
		"no scopes":       user(),
		"anonymous":       nil,
		"admin-lookalike": user("chronicle.administrator", "admin"),
	} {
		if p.Allow(u, nil) {
			t.Errorf("allows %s", name)
		}
	}
}

// An erasure changes what the erasure list, the preview count, the overview
// tile and every read of events show. It changes no stored byte, so it must
// not claim to change a verification verdict: the client refreshes on
// invalidates, and a verify.* entry here would rerun a walk of the chain for
// nothing.
func TestErasureRequestDeclaresEverythingItChangesAndNoVerification(t *testing.T) {
	got := erasureRequestIntent(t).Invalidates
	want := []string{"erasures.list", "erasures.preview", "overview.stats",
		"events.list", "events.detail", "events.byUser"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("invalidates %v, want %v", got, want)
	}
	for _, name := range got {
		if strings.HasPrefix(name, "verify.") {
			t.Errorf("invalidates %s: an erasure never changes a stored hash", name)
		}
	}
}

// ──────────────────────────────────────────────────
// Who asked, and where it runs
// ──────────────────────────────────────────────────

// RequestedBy is the evidence of who ordered a destruction. It is the one
// field most tempting to accept from the request, and accepting it would let a
// caller attribute an erasure to somebody else.
func TestErasureRequestTakesRequestedByFromThePrincipal(t *testing.T) {
	spy := &erasureRequestSpyStore{}
	h := erasuresRequestHandler(spy.deps())

	// The payload names someone else. The input type has no such field, so
	// decoding drops it; the handler must still stamp the signed-in user.
	var in RequestErasureInput
	raw := `{"subjectId":"user-42","reason":"gdpr article 17","requestedBy":"mallory"}`
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, err := h(context.Background(), in, erasureAdmin(map[string]any{"app_id": "app-1"})); err != nil {
		t.Fatalf("erasures.request: %v", err)
	}
	if len(spy.recorded) != 1 {
		t.Fatalf("recorded %d erasures, want 1", len(spy.recorded))
	}
	if got := spy.recorded[0].RequestedBy; got != "dpo-9" {
		t.Fatalf("RequestedBy = %q, want the principal's subject dpo-9", got)
	}
}

// Every place Erase acts must see the viewer's scope. erasure.Scope's own doc
// says a zero scope matches every app and tenant, so a wrong argument here is
// the difference between one tenant's erasure and everyone's.
func TestErasureRequestRunsInTheViewersScope(t *testing.T) {
	for _, tc := range []struct {
		name         string
		claims       map[string]any
		app, tenant  string
		recordTenant string
	}{
		{"app-wide viewer", map[string]any{"app_id": "app-1"}, "app-1", "", ""},
		{"tenant viewer", map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"}, "app-1", "tenant-a", "tenant-a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spy := &erasureRequestSpyStore{count: 3, affected: 3}
			h := erasuresRequestHandler(spy.deps())
			if _, err := h(context.Background(), erasureRequestIn("user-42", "r"), erasureAdmin(tc.claims)); err != nil {
				t.Fatalf("erasures.request: %v", err)
			}

			want := erasure.Scope{AppID: tc.app, TenantID: tc.tenant}
			if len(spy.counted) != 1 || spy.counted[0].Scope != want {
				t.Errorf("counted in %+v, want %+v", spy.counted, want)
			}
			if len(spy.marked) != 1 || spy.marked[0].Scope != want {
				t.Errorf("marked in %+v, want %+v", spy.marked, want)
			}
			if len(spy.recorded) != 1 || spy.recorded[0].AppID != tc.app || spy.recorded[0].TenantID != tc.tenant {
				t.Errorf("recorded %+v, want app %q tenant %q", spy.recorded, tc.app, tc.tenant)
			}
		})
	}
}

// A request cannot carry its own scope, and a session with no usable app is
// refused before the service is touched.
func TestErasureRequestRefusesASessionWithNoAppBeforeErasing(t *testing.T) {
	spy := &erasureRequestSpyStore{}
	h := erasuresRequestHandler(spy.deps())
	_, err := h(context.Background(), erasureRequestIn("user-42", "r"), erasureAdmin(map[string]any{}))
	if !errors.Is(err, fcontract.ErrPermissionDenied) {
		t.Fatalf("err = %v, want PERMISSION_DENIED", err)
	}
	if spy.touched() {
		t.Fatal("Erase ran for a session with no app")
	}
}

// scopeFromPrincipal cannot hand back an empty app today, but an empty one
// means every app to Service.Erase, so the handler asserts it itself.
func TestErasureScopeRefusesAnEmptyApp(t *testing.T) {
	for _, v := range []viewScope{{}, {TenantID: "tenant-a"}} {
		if _, _, err := erasureScope(v); !errors.Is(err, fcontract.ErrPermissionDenied) {
			t.Errorf("erasureScope(%+v) = %v, want PERMISSION_DENIED", v, err)
		}
	}
	app, tenant, err := erasureScope(viewScope{AppID: "app-1", TenantID: "tenant-a"})
	if err != nil || app != "app-1" || tenant != "tenant-a" {
		t.Errorf("erasureScope of a real scope = %q, %q, %v", app, tenant, err)
	}
}

// ──────────────────────────────────────────────────
// Input
// ──────────────────────────────────────────────────

func TestErasureRequestRefusesBadInputBeforeErasing(t *testing.T) {
	multibyte := func(n int) string { return strings.Repeat("é", n) } // 2 bytes, 1 rune

	for _, tc := range []struct {
		name    string
		subject string
		reason  string
		refused bool
	}{
		{"complete", "user-42", "gdpr article 17", false},
		{"no subject", "", "r", true},
		{"no reason", "user-42", "", true},
		{"whitespace-only reason", "user-42", " \n\t ", true},

		{"subject at 256 runes", strings.Repeat("s", 256), "r", false},
		{"subject at 257 runes", strings.Repeat("s", 257), "r", true},
		{"subject of 256 multibyte runes (512 bytes)", multibyte(256), "r", false},
		{"subject of 257 multibyte runes", multibyte(257), "r", true},
		{"subject with an interior space", "user 42", "r", false},
		{"subject with leading space", " user-42", "r", true},
		{"subject with trailing space", "user-42 ", "r", true},
		{"subject with trailing newline", "user-42\n", "r", true},
		{"subject with leading no-break space", " user-42", "r", true},
		{"subject with an interior tab", "user\t42", "r", true},
		{"subject with a NUL", "user\x0042", "r", true},
		{"subject with DEL", "user\x7f42", "r", true},
		{"subject with an interior newline", "user\n42", "r", true},
		{"subject that is not UTF-8", "user-\xff42", "r", true},

		{"reason at 2000 runes", "user-42", strings.Repeat("r", 2000), false},
		{"reason at 2001 runes", "user-42", strings.Repeat("r", 2001), true},
		{"reason of 2000 multibyte runes (4000 bytes)", "user-42", multibyte(2000), false},
		{"reason of 2001 multibyte runes", "user-42", multibyte(2001), true},
		{"reason with newlines", "user-42", "Art. 17 request.\nReceived by email.\n", false},
		{"reason with a tab", "user-42", "a\tb", true},
		{"reason with a carriage return", "user-42", "a\r\nb", true},
		{"reason with a NUL", "user-42", "a\x00b", true},
		{"reason with an escape", "user-42", "a\x1b[31mb", true},
		{"reason that is not UTF-8", "user-42", "a\xffb", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spy := &erasureRequestSpyStore{}
			h := erasuresRequestHandler(spy.deps())
			_, err := h(context.Background(), erasureRequestIn(tc.subject, tc.reason),
				erasureAdmin(map[string]any{"app_id": "app-1"}))
			if tc.refused {
				if !errors.Is(err, fcontract.ErrBadRequest) {
					t.Fatalf("err = %v, want BAD_REQUEST", err)
				}
				if spy.touched() {
					t.Fatal("Erase ran for a refused request")
				}
				return
			}
			if err != nil {
				t.Fatalf("refused a valid request: %v", err)
			}
			if len(spy.recorded) != 1 {
				t.Fatalf("recorded %d erasures, want 1", len(spy.recorded))
			}
			// Stored as written, never trimmed or repaired.
			if spy.recorded[0].SubjectID != tc.subject || spy.recorded[0].Reason != tc.reason {
				t.Errorf("recorded subject %q reason %q, want them verbatim", spy.recorded[0].SubjectID, spy.recorded[0].Reason)
			}
		})
	}
}

// ──────────────────────────────────────────────────
// Availability and errors
// ──────────────────────────────────────────────────

func TestErasureRequestIsUnavailableWithoutTheService(t *testing.T) {
	h := erasuresRequestHandler(Deps{Store: newStubStore()})
	_, err := h(context.Background(), erasureRequestIn("user-42", "r"), erasureAdmin(map[string]any{"app_id": "app-1"}))
	if !errors.Is(err, fcontract.ErrUnavailable) {
		t.Fatalf("err = %v, want UNAVAILABLE", err)
	}
	if !strings.Contains(err.Error(), "enable_crypto_erasure") {
		t.Errorf("message %q does not name the setting to turn on", err.Error())
	}
}

// The scope check comes first: an unavailable answer to a session that has no
// business here would say which deployments run erasure.
func TestErasureRequestChecksTheSessionBeforeAvailability(t *testing.T) {
	h := erasuresRequestHandler(Deps{Store: newStubStore()})
	_, err := h(context.Background(), erasureRequestIn("user-42", "r"), fcontract.Principal{})
	if !errors.Is(err, fcontract.ErrUnauthenticated) {
		t.Fatalf("err = %v, want UNAUTHENTICATED", err)
	}
}

// A store failure reaches the caller as a generic internal error. The cause
// stays in the log.
func TestErasureRequestMapsAStoreFailureToInternal(t *testing.T) {
	spy := &erasureRequestSpyStore{recordErr: errors.New("pq: connection refused at 10.0.0.7")}
	_, err := erasuresRequestHandler(spy.deps())(context.Background(), erasureRequestIn("user-42", "r"),
		erasureAdmin(map[string]any{"app_id": "app-1"}))
	if !errors.Is(err, fcontract.ErrInternal) {
		t.Fatalf("err = %v, want INTERNAL", err)
	}
	if strings.Contains(err.Error(), "10.0.0.7") {
		t.Errorf("the store's own message reached the caller: %v", err)
	}
}

// ──────────────────────────────────────────────────
// The result on the wire
// ──────────────────────────────────────────────────

// A key sealed before keys were scoped, still used by live events in another
// app, is kept. The events are marked erased but the erasure is not
// cryptographic yet, and the page needs to be able to say so.
func TestErasureRequestReportsARetainedLegacyKey(t *testing.T) {
	spy := &erasureRequestSpyStore{
		count: 2, affected: 2,
		usage: []erasure.KeyUsage{
			{Scope: erasure.Scope{AppID: "app-1"}, EncryptionKeyID: "user-42", Events: 2},
			{Scope: erasure.Scope{AppID: "app-2"}, EncryptionKeyID: "user-42", Events: 1},
		},
	}
	out, err := erasuresRequestHandler(spy.deps())(context.Background(), erasureRequestIn("user-42", "r"),
		erasureAdmin(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("erasures.request: %v", err)
	}
	if out.KeyDestroyed || !out.LegacyKeyRetained {
		t.Fatalf("result = %+v, want keyDestroyed false and legacyKeyRetained true", out)
	}
	if out.EventsAffected != 2 || out.SubjectID != "user-42" {
		t.Errorf("result = %+v, want 2 events for user-42", out)
	}
	if _, err := id.ParseErasureID(out.ID); err != nil {
		t.Errorf("ID %q is not an erasure ID: %v", out.ID, err)
	}

	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if wire["legacyKeyRetained"] != true || wire["keyDestroyed"] != false {
		t.Errorf("wire = %s, want legacyKeyRetained true and keyDestroyed false", raw)
	}

	// And the record the erasure left says the same, so the detail page can
	// say it later.
	if len(spy.recorded) != 1 || spy.recorded[0].KeyDestroyed {
		t.Errorf("recorded %+v, want an erasure with KeyDestroyed false", spy.recorded)
	}
}

// legacyKeyRetained is on the wire when false too. If it dropped out, a page
// could not tell "kept nothing" from a server that never said.
func TestErasureResultAlwaysCarriesLegacyKeyRetained(t *testing.T) {
	spy := &erasureRequestSpyStore{count: 1, affected: 1}
	out, err := erasuresRequestHandler(spy.deps())(context.Background(), erasureRequestIn("user-42", "r"),
		erasureAdmin(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("erasures.request: %v", err)
	}
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"id", "subjectId", "eventsAffected", "keyDestroyed", "legacyKeyRetained"} {
		if _, ok := wire[key]; !ok {
			t.Errorf("wire %s has no %q", raw, key)
		}
	}
	if wire["legacyKeyRetained"] != false || wire["keyDestroyed"] != true {
		t.Errorf("wire = %s, want keyDestroyed true and legacyKeyRetained false", raw)
	}
}

// The detail page reads keyDestroyed from the stored record, which is how it
// can show the same thing later. A record that kept its key says false.
func TestErasureDetailProjectsAKeyThatWasKept(t *testing.T) {
	realID := id.NewErasureID()
	h := erasuresDetailHandler(Deps{Store: storeWithErasure(&erasure.Erasure{
		ID: realID, AppID: "app-1", SubjectID: "user-42", KeyDestroyed: false,
	})})
	out, err := h(context.Background(), GetErasureInput{ID: realID.String()},
		principalWith(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("erasures.detail: %v", err)
	}
	if out.KeyDestroyed {
		t.Error("KeyDestroyed = true for a record that kept its key")
	}
	raw, _ := json.Marshal(out)
	if !strings.Contains(string(raw), `"keyDestroyed":false`) {
		t.Errorf("wire %s does not carry keyDestroyed false", raw)
	}
}

// ──────────────────────────────────────────────────
// End to end on a real store with sealed events
// ──────────────────────────────────────────────────

// erasureSealed is a sqlite store wrapped the way the extension wraps it when
// crypto-erasure is on, with a Chronicle that seals what it records and an
// erasure service over the same store and key store.
type erasureSealed struct {
	chronicle *chronicle.Chronicle
	store     store.Store
	deps      Deps
}

func newErasureSealed(t *testing.T) erasureSealed {
	t.Helper()
	keys := crypto.NewInMemoryKeyStore()
	sealer := crypto.NewSealer(keys)
	sealed := sealedstore.New(newSQLiteStore(t), sealer)

	c, err := chronicle.New(
		chronicle.WithStore(store.NewAdapter(sealed)),
		chronicle.WithCryptoErasure(true),
		chronicle.WithSealer(sealer),
	)
	if err != nil {
		t.Fatalf("chronicle.New: %v", err)
	}
	return erasureSealed{
		chronicle: c,
		store:     sealed,
		deps:      Deps{Store: sealed, Chronicle: c, Erasure: erasure.NewService(sealed, keys)},
	}
}

// record writes one event for subjectID in app and tenant, with a reason and
// metadata the sealer encrypts.
func (e erasureSealed) record(t *testing.T, app, tenant, subjectID, reason string) {
	t.Helper()
	ctx := scope.WithAppID(context.Background(), app)
	if tenant != "" {
		ctx = scope.WithTenantID(ctx, tenant)
	}
	if err := e.chronicle.Record(ctx, &audit.Event{
		Action:    "export",
		Resource:  "user",
		Category:  "data",
		SubjectID: subjectID,
		Reason:    reason,
		IP:        "203.0.113.9",
		Metadata:  map[string]any{"email": reason + "@example.com"},
	}); err != nil {
		t.Fatalf("Record %s/%s: %v", app, tenant, err)
	}
}

// read returns the events the store holds for a scope, as every reader sees
// them: through the sealed wrapper, decrypted where the key exists.
func (e erasureSealed) read(t *testing.T, app, tenant string) []*audit.Event {
	t.Helper()
	res, err := e.store.Query(context.Background(), &audit.Query{AppID: app, TenantID: tenant, Limit: 100})
	if err != nil {
		t.Fatalf("Query %s/%s: %v", app, tenant, err)
	}
	return res.Events
}

// assertReadable fails unless every event still decrypts to what was recorded.
func assertReadable(t *testing.T, label string, events []*audit.Event, wantReasons ...string) {
	t.Helper()
	if len(events) != len(wantReasons) {
		t.Fatalf("%s: %d events, want %d", label, len(events), len(wantReasons))
	}
	got := map[string]bool{}
	for _, ev := range events {
		if ev.Erased {
			t.Errorf("%s: event %s is flagged erased", label, ev.ID)
		}
		if ev.IP != "203.0.113.9" {
			t.Errorf("%s: IP = %q, want the original", label, ev.IP)
		}
		got[ev.Reason] = true
	}
	for _, want := range wantReasons {
		if !got[want] {
			t.Errorf("%s: no event reads back with reason %q (got %v)", label, want, got)
		}
	}
}

// assertErased fails unless every event is flagged erased and shows nothing.
func assertErased(t *testing.T, label string, events []*audit.Event, n int) {
	t.Helper()
	if len(events) != n {
		t.Fatalf("%s: %d events, want %d", label, len(events), n)
	}
	for _, ev := range events {
		if !ev.Erased {
			t.Errorf("%s: event %s is not flagged erased", label, ev.ID)
		}
		if ev.Reason != crypto.ErasedMarker {
			t.Errorf("%s: Reason = %q, want %q", label, ev.Reason, crypto.ErasedMarker)
		}
		if ev.IP == "203.0.113.9" {
			t.Errorf("%s: the IP is still readable after erasure", label)
		}
	}
}

// listErasures is what the erasure page would show a viewer.
func (e erasureSealed) listErasures(t *testing.T, p fcontract.Principal) ErasureListResponse {
	t.Helper()
	out, err := erasuresListHandler(e.deps)(context.Background(), ErasureListInput{}, p)
	if err != nil {
		t.Fatalf("erasures.list: %v", err)
	}
	return out
}

// This is the regression that held the command back. Two apps record events
// for the same subject ID. One app erases it. That used to destroy the single
// key both shared, so the other app's events read back as erased with no
// erasure record in its own scope to explain it.
func TestErasureRequestLeavesAnotherAppsEventsAlone(t *testing.T) {
	e := newErasureSealed(t)
	e.record(t, "app-1", "", "user-42", "mine")
	e.record(t, "app-2", "", "user-42", "theirs")

	app1 := erasureAdmin(map[string]any{"app_id": "app-1"})
	app2 := erasureAdmin(map[string]any{"app_id": "app-2"})

	out, err := erasuresRequestHandler(e.deps)(context.Background(), erasureRequestIn("user-42", "gdpr article 17"), app1)
	if err != nil {
		t.Fatalf("erasures.request: %v", err)
	}
	if out.EventsAffected != 1 || !out.KeyDestroyed || out.LegacyKeyRetained {
		t.Fatalf("result = %+v, want 1 event, key destroyed, nothing retained", out)
	}

	assertErased(t, "app-1", e.read(t, "app-1", ""), 1)
	assertReadable(t, "app-2", e.read(t, "app-2", ""), "theirs")

	if got := e.listErasures(t, app2); got.Total != 0 || len(got.Erasures) != 0 {
		t.Errorf("app-2 sees %d erasure records after app-1's erasure, want none", got.Total)
	}
	mine := e.listErasures(t, app1)
	if mine.Total != 1 || len(mine.Erasures) != 1 {
		t.Fatalf("app-1 sees %d erasure records, want 1", mine.Total)
	}
	if got := mine.Erasures[0]; got.ID != out.ID || got.RequestedBy != "dpo-9" || !got.KeyDestroyed {
		t.Errorf("app-1's record = %+v, want the erasure just made, by dpo-9, key destroyed", got)
	}
}

// The same probe one level down: two tenants of one app, and the app's own
// untenanted events beside them. A tenant viewer's erasure stays in its
// tenant: the sibling's events and the app-level events keep decrypting. An
// empty tenant means "any" to every store query, so a tenant scope that also
// covered tenant "" would destroy the app-level key along the way.
func TestErasureRequestLeavesASiblingTenantsEventsAlone(t *testing.T) {
	e := newErasureSealed(t)
	e.record(t, "app-1", "tenant-a", "user-42", "a-event")
	e.record(t, "app-1", "tenant-b", "user-42", "b-event")
	e.record(t, "app-1", "", "user-42", "app-level-event")

	tenantA := erasureAdmin(map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"})
	tenantB := erasureAdmin(map[string]any{"app_id": "app-1", "tenant_id": "tenant-b"})

	out, err := erasuresRequestHandler(e.deps)(context.Background(), erasureRequestIn("user-42", "gdpr article 17"), tenantA)
	if err != nil {
		t.Fatalf("erasures.request: %v", err)
	}
	if out.EventsAffected != 1 || !out.KeyDestroyed {
		t.Fatalf("result = %+v, want 1 event and the key destroyed", out)
	}

	assertErased(t, "tenant-a", e.read(t, "app-1", "tenant-a"), 1)
	assertReadable(t, "tenant-b", e.read(t, "app-1", "tenant-b"), "b-event")

	// Reading app-1 with no tenant returns every tenant's events, so keep the
	// app-level ones by their own empty TenantID.
	var appLevel []*audit.Event
	for _, ev := range e.read(t, "app-1", "") {
		if ev.TenantID == "" {
			appLevel = append(appLevel, ev)
		}
	}
	assertReadable(t, "app-level", appLevel, "app-level-event")

	if got := e.listErasures(t, tenantB); got.Total != 0 {
		t.Errorf("tenant-b sees %d erasure records after tenant-a's erasure, want none", got.Total)
	}
	if got := e.listErasures(t, tenantA); got.Total != 1 {
		t.Errorf("tenant-a sees %d erasure records, want 1", got.Total)
	}
}

// An app-wide viewer's erasure covers every tenant in its own app, which is
// what app-wide means, and still stops at the app boundary.
func TestErasureRequestByAnAppWideViewerCoversItsTenantsAndNoOtherApp(t *testing.T) {
	e := newErasureSealed(t)
	e.record(t, "app-1", "tenant-a", "user-42", "a-event")
	e.record(t, "app-1", "tenant-b", "user-42", "b-event")
	e.record(t, "app-2", "tenant-a", "user-42", "other-app-event")

	out, err := erasuresRequestHandler(e.deps)(context.Background(), erasureRequestIn("user-42", "gdpr article 17"),
		erasureAdmin(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("erasures.request: %v", err)
	}
	if out.EventsAffected != 2 || !out.KeyDestroyed {
		t.Fatalf("result = %+v, want 2 events and the key destroyed", out)
	}

	assertErased(t, "app-1 tenant-a", e.read(t, "app-1", "tenant-a"), 1)
	assertErased(t, "app-1 tenant-b", e.read(t, "app-1", "tenant-b"), 1)
	assertReadable(t, "app-2 tenant-a", e.read(t, "app-2", "tenant-a"), "other-app-event")
}

// Erasure changes no stored byte, so a chain that verified before still
// verifies after. This is why the manifest lists no verify intent.
func TestErasureRequestDoesNotChangeWhatVerificationSees(t *testing.T) {
	e := newErasureSealed(t)
	e.record(t, "app-1", "", "user-42", "mine")
	e.record(t, "app-1", "", "user-42", "mine-too")

	app1 := erasureAdmin(map[string]any{"app_id": "app-1"})
	run := func() *VerifyReport {
		out, err := verifyRunHandler(e.deps)(context.Background(), VerifyInput{}, app1)
		if err != nil {
			t.Fatalf("verify.run: %v", err)
		}
		if out.Report == nil {
			t.Fatal("verify.run produced no report for a chain with events")
		}
		return out.Report
	}
	before := run()
	if !before.Valid || before.Verified != 2 {
		t.Fatalf("chain before the erasure = %+v, want 2 events verified", before)
	}

	if _, err := erasuresRequestHandler(e.deps)(context.Background(), erasureRequestIn("user-42", "r"), app1); err != nil {
		t.Fatalf("erasures.request: %v", err)
	}
	after := run()

	if !after.Valid || after.Verified != before.Verified || len(after.Tampered) != 0 {
		t.Errorf("verification changed across an erasure: before %+v, after %+v", before, after)
	}
}

// The detail and list pages read status and legacyKeyRetained from the stored
// record. A pending erasure says pending, a retained legacy key says so, and a
// record from before erasures had a status reads as completed. Both fields are
// on the wire every time, so a page never has to guess what a missing one means.
func TestErasureSummaryProjectsStatusAndLegacyKey(t *testing.T) {
	cases := []struct {
		name       string
		rec        erasure.Erasure
		wantStatus string
		wantLegacy bool
	}{
		{"pending", erasure.Erasure{Status: erasure.StatusPending}, "pending", false},
		{"legacy key retained", erasure.Erasure{Status: erasure.StatusCompleted, LegacyKeyRetained: true}, "completed", true},
		{"before statuses", erasure.Erasure{KeyDestroyed: true}, "completed", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := tc.rec
			rec.ID = id.NewErasureID()
			rec.AppID = "app-1"
			rec.SubjectID = "user-42"
			h := erasuresDetailHandler(Deps{Store: storeWithErasure(&rec)})
			out, err := h(context.Background(), GetErasureInput{ID: rec.ID.String()},
				principalWith(map[string]any{"app_id": "app-1"}))
			if err != nil {
				t.Fatalf("erasures.detail: %v", err)
			}

			raw, err := json.Marshal(out)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var wire map[string]any
			if err := json.Unmarshal(raw, &wire); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if wire["status"] != tc.wantStatus || wire["legacyKeyRetained"] != tc.wantLegacy {
				t.Errorf("wire = %s, want status %q and legacyKeyRetained %v", raw, tc.wantStatus, tc.wantLegacy)
			}
		})
	}
}
