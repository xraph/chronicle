package contract

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xraph/grove"
	"github.com/xraph/grove/drivers/sqlitedriver"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/keys"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
	"github.com/xraph/chronicle/store/sqlite"
	"github.com/xraph/chronicle/stream"
	"github.com/xraph/chronicle/verify"
)

// Every checked flag has to survive the projection. This is the one test
// that would catch somebody "simplifying" the DTO by dropping a flag whose
// value looked redundant next to its partner.
func TestVerifyReportCarriesEveryCheckedFlag(t *testing.T) {
	src := &verify.Report{
		Valid: false, Verified: 9, FirstEvent: 1, LastEvent: 9, HeadSeq: 12,
		Partial:               true,
		Gaps:                  []uint64{4},
		Tampered:              []uint64{7},
		Downgrades:            []uint64{8},
		Tolerant:              []uint64{2},
		HeadMatch:             false,
		HeadChecked:           true,
		CheckpointsChecked:    true,
		CheckpointHeadOK:      false,
		CheckpointHeadChecked: true,
		Coverage: []verify.Coverage{
			{FromSeq: 1, ToSeq: 5, Level: verify.LevelUnkeyed, Note: "below the pin"},
			{FromSeq: 6, ToSeq: 9, Level: verify.LevelKeyed},
		},
		Checkpoints: []verify.CheckpointResult{{
			ID: "cp_1", FromSeq: 1, ToSeq: 5,
			SignatureValid: true,
			HashMatch:      false, HashChecked: false,
			ContinuityOK: true, ContinuityChecked: true,
			Note: "to_seq falls outside the verified range; hash not re-checked",
		}},
	}

	got := projectReport(src)

	if !got.Partial || !got.HeadChecked || got.HeadMatch {
		t.Error("head fields did not survive projection")
	}
	if !got.CheckpointsChecked || !got.CheckpointHeadChecked || got.CheckpointHeadOK {
		t.Error("checkpoint head fields did not survive projection")
	}
	if len(got.Coverage) != 2 {
		t.Fatalf("coverage spans = %d, want 2: a chain with a pin has more than one level", len(got.Coverage))
	}
	if got.Coverage[0].Note == "" {
		t.Error("the coverage note was dropped; it is what explains a span below the pin")
	}
	cp := got.Checkpoints[0]
	if cp.HashChecked || cp.HashMatch {
		t.Error("an unchecked hash must project as unchecked, not as a mismatch")
	}
	if !cp.ContinuityChecked || !cp.ContinuityOK {
		t.Error("continuity fields did not survive projection")
	}
	if cp.Note == "" {
		t.Error("the checkpoint note was dropped; it is what tells the operator why it was not checked")
	}

	// The spot checks above read well as failure messages but do not, on
	// their own, prove every field survived: Valid, Verified, the slices
	// (Gaps/Tampered/Downgrades/Tolerant), FirstEvent/LastEvent/HeadSeq, each
	// coverage span's own FromSeq/ToSeq/Level, and each checkpoint's
	// ID/FromSeq/ToSeq/SignatureValid could all be silently hardcoded,
	// dropped, or mis-copied and none of the checks above would notice. A
	// full structural comparison against the exact expected wire value is
	// the only thing that catches all of those at once.
	want := &VerifyReport{
		Valid: false, Verified: 9, FirstEvent: 1, LastEvent: 9, HeadSeq: 12,
		Gaps:       []uint64{4},
		Tampered:   []uint64{7},
		Downgrades: []uint64{8},
		Tolerant:   []uint64{2},

		Partial:     true,
		HeadMatch:   false,
		HeadChecked: true,

		CheckpointsChecked:    true,
		CheckpointHeadOK:      false,
		CheckpointHeadChecked: true,

		Coverage: []CoverageSpan{
			{FromSeq: 1, ToSeq: 5, Level: string(verify.LevelUnkeyed), Note: "below the pin"},
			{FromSeq: 6, ToSeq: 9, Level: string(verify.LevelKeyed)},
		},
		Checkpoints: []CheckpointResult{{
			ID: "cp_1", FromSeq: 1, ToSeq: 5,
			SignatureValid: true,
			HashMatch:      false, HashChecked: false,
			ContinuityOK: true, ContinuityChecked: true,
			Note: "to_seq falls outside the verified range; hash not re-checked",
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("projectReport dropped, hardcoded, or mis-copied a field:\n got  = %+v\n  (checkpoints: %+v, coverage: %+v)\n want = %+v\n  (checkpoints: %+v, coverage: %+v)",
			got, got.Checkpoints, got.Coverage, want, want.Checkpoints, want.Coverage)
	}
}

// The JSON encoding is the only thing that actually enforces "no omitempty
// on a checked flag or its value partner": a struct-level assertion cannot
// see whether a false bool serialised at all. Marshal an all-false,
// all-empty report (plus one all-zero checkpoint result, so its fields are
// covered too) and require every checked flag and its partner to appear as
// a JSON key, present with value false, rather than being omitted.
func TestVerifyReportJSONNeverOmitsACheckedFlagOrItsPartner(t *testing.T) {
	report := VerifyReport{
		Checkpoints: []CheckpointResult{{}},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, key := range []string{
		"valid", "verified", "firstEvent", "lastEvent", "headSeq",
		"partial", "headMatch", "headChecked",
		"checkpointsChecked", "checkpointHeadOk", "checkpointHeadChecked",
		"retentionPolicies",
	} {
		msg, ok := raw[key]
		if !ok {
			t.Errorf("marshaled report omits %q for its false/zero value; omitempty was added back", key)
			continue
		}
		numeric := map[string]bool{"verified": true, "firstEvent": true, "lastEvent": true, "headSeq": true, "retentionPolicies": true}
		if numeric[key] && string(msg) != "0" {
			t.Errorf("%q = %s, want 0", key, msg)
		}
		if string(msg) != "false" && !numeric[key] {
			t.Errorf("%q = %s, want false", key, msg)
		}
	}

	var cps []map[string]json.RawMessage
	if err := json.Unmarshal(raw["checkpoints"], &cps); err != nil {
		t.Fatalf("unmarshal checkpoints: %v", err)
	}
	if len(cps) != 1 {
		t.Fatalf("checkpoints = %d entries, want 1", len(cps))
	}
	for _, key := range []string{
		"id", "fromSeq", "toSeq",
		"signatureValid", "hashMatch", "hashChecked", "continuityOk", "continuityChecked",
	} {
		if _, ok := cps[0][key]; !ok {
			t.Errorf("marshaled checkpoint result omits %q for its false/zero value", key)
		}
	}
}

// Review Focus 4: a scope whose chain does not exist yet. Chronicle creates
// a stream on the first Record, so a fresh app has none, and asking to
// verify it must answer "no chain yet" rather than dereferencing nil.
func TestVerifyRunOnAScopeWithNoChain(t *testing.T) {
	h := verifyRunHandler(Deps{Store: storeReturning(chronicle.ErrStreamNotFound)})
	out, err := h(context.Background(), VerifyInput{}, principalWith(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("verify on a scope with no chain errored: %v", err)
	}
	if out.Report != nil {
		t.Error("expected no report for a scope that has never recorded an event")
	}
	if !out.NoChain {
		t.Error("NoChain must say so explicitly; a nil report alone is ambiguous")
	}
}

func TestVerifyRunRefusesAPrincipalWithNoApp(t *testing.T) {
	h := verifyRunHandler(Deps{Store: newStubStore()})
	if _, err := h(context.Background(), VerifyInput{}, principalWith(nil)); err == nil {
		t.Fatal("verify served a principal with no app scope")
	}
}

// verifySpanStore answers GetStreamByScope with a fixed stream and counts
// the calls VerifyChain itself makes (EventRange, Gaps), so a test can prove
// the span cap refused a request before VerifyChain ever touched the store.
// EventRange answers with events, when set, so the same store can also drive
// tests that need VerifyChain to see specific rows (e.g. a downgrade).
type verifySpanStore struct {
	stubStore
	st         *stream.Stream
	events     []*audit.Event
	eventRange int
	gaps       int
}

func (s *verifySpanStore) GetStreamByScope(context.Context, string, string) (*stream.Stream, error) {
	return s.st, nil
}

func (s *verifySpanStore) EventRange(context.Context, id.ID, uint64, uint64) ([]*audit.Event, error) {
	s.eventRange++
	return s.events, nil
}

func (s *verifySpanStore) Gaps(context.Context, id.ID, uint64, uint64) ([]uint64, error) {
	s.gaps++
	return nil, nil
}

func (s *verifySpanStore) touched() int { return s.eventRange + s.gaps }

// A bounded request whose resolved span is under the cap must
// reach VerifyChain, and therefore the store.
func TestVerifyRunVerifiesASpanUnderTheCap(t *testing.T) {
	s := &verifySpanStore{st: &stream.Stream{
		ID: id.NewStreamID(), AppID: "app-1",
		HeadSeq: 10, HeadHash: "head-hash",
		Scheme: string(hash.SchemePlainV4), SchemeSince: 1,
	}}
	h := verifyRunHandler(Deps{Store: s})

	out, err := h(context.Background(), VerifyInput{}, principalWith(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("verify.run under the cap: %v", err)
	}
	if out.Report == nil {
		t.Fatal("expected a report for a span under the cap")
	}
	if s.touched() == 0 {
		t.Fatal("VerifyChain never touched the store for a span under the cap")
	}
}

// A span over the cap must be refused before VerifyChain runs at
// all -- proved here by the store never seeing EventRange or Gaps -- and the
// refusal must name both the cap and the chain's head so the UI can offer a
// bounded window.
func TestVerifyRunRefusesASpanOverTheCap(t *testing.T) {
	const headSeq = maxVerifySpan + 500
	s := &verifySpanStore{st: &stream.Stream{
		ID: id.NewStreamID(), AppID: "app-1",
		HeadSeq: headSeq, HeadHash: "head-hash",
		Scheme: string(hash.SchemePlainV4), SchemeSince: 1,
	}}
	h := verifyRunHandler(Deps{Store: s})

	_, err := h(context.Background(), VerifyInput{FromSeq: 1, ToSeq: maxVerifySpan + 1},
		principalWith(map[string]any{"app_id": "app-1"}))

	var ce *fcontract.Error
	if !errors.As(err, &ce) || ce.Code != fcontract.CodeBadRequest {
		t.Fatalf("err = %v, want BAD_REQUEST", err)
	}
	if !strings.Contains(ce.Error(), fmt.Sprintf("%d-event", maxVerifySpan)) {
		t.Errorf("error does not name the cap: %q", ce.Error())
	}
	if !strings.Contains(ce.Error(), fmt.Sprintf("sequence %d", headSeq)) {
		t.Errorf("error does not name the chain's head: %q", ce.Error())
	}
	if s.touched() != 0 {
		t.Fatalf("VerifyChain touched the store (eventRange=%d gaps=%d) before the cap refused it", s.eventRange, s.gaps)
	}
}

// FromSeq 0, toSeq 0 -- "verify everything" -- against a chain
// longer than the cap must refuse the same as an explicit over-cap range,
// since it resolves to exactly that.
func TestVerifyRunRefusesZeroZeroOnAChainLongerThanTheCap(t *testing.T) {
	s := &verifySpanStore{st: &stream.Stream{
		ID: id.NewStreamID(), AppID: "app-1",
		HeadSeq: maxVerifySpan + 1, HeadHash: "head-hash",
		Scheme: string(hash.SchemePlainV4), SchemeSince: 1,
	}}
	h := verifyRunHandler(Deps{Store: s})

	_, err := h(context.Background(), VerifyInput{}, principalWith(map[string]any{"app_id": "app-1"}))

	var ce *fcontract.Error
	if !errors.As(err, &ce) || ce.Code != fcontract.CodeBadRequest {
		t.Fatalf("err = %v, want BAD_REQUEST", err)
	}
	if s.touched() != 0 {
		t.Fatalf("VerifyChain touched the store on a 0/0 request over the cap")
	}
}

// A reversed range is refused after resolution, before it can
// underflow the span computation or reach VerifyChain.
func TestVerifyRunRefusesAReversedRange(t *testing.T) {
	s := &verifySpanStore{st: &stream.Stream{
		ID: id.NewStreamID(), AppID: "app-1",
		HeadSeq: 100, HeadHash: "head-hash",
		Scheme: string(hash.SchemePlainV4), SchemeSince: 1,
	}}
	h := verifyRunHandler(Deps{Store: s})

	_, err := h(context.Background(), VerifyInput{FromSeq: 10, ToSeq: 5}, principalWith(map[string]any{"app_id": "app-1"}))

	var ce *fcontract.Error
	if !errors.As(err, &ce) || ce.Code != fcontract.CodeBadRequest {
		t.Fatalf("err = %v, want BAD_REQUEST", err)
	}
	if s.touched() != 0 {
		t.Fatalf("VerifyChain touched the store on a reversed range")
	}
}

// Deps.MaxVerifySpan overrides the package default; zero means
// use it.
func TestVerifyRunCapIsOverridableThroughDeps(t *testing.T) {
	s := &verifySpanStore{st: &stream.Stream{
		ID: id.NewStreamID(), AppID: "app-1",
		HeadSeq: 100, HeadHash: "head-hash",
		Scheme: string(hash.SchemePlainV4), SchemeSince: 1,
	}}
	h := verifyRunHandler(Deps{Store: s, MaxVerifySpan: 10})

	_, err := h(context.Background(), VerifyInput{}, principalWith(map[string]any{"app_id": "app-1"}))

	var ce *fcontract.Error
	if !errors.As(err, &ce) || ce.Code != fcontract.CodeBadRequest {
		t.Fatalf("err = %v, want BAD_REQUEST", err)
	}
	if !strings.Contains(ce.Error(), "10-event") {
		t.Errorf("error does not name the overridden cap: %q", ce.Error())
	}
	if s.touched() != 0 {
		t.Fatalf("VerifyChain touched the store past the overridden cap")
	}
}

// A ToSeq resolved from the stream's own head -- as
// opposed to one the caller supplied -- must never be refused as "reversed",
// even when the head is 0. A wiped chain (every event deleted, the head row
// zeroed) resolves fromSeq 1, toSeq 0 on a bare VerifyInput{}, and that is
// exactly the shape checkClaimedHead exists to catch: a signed checkpoint
// still asserting events the head no longer claims. This reproduces the
// library's own TestTotalWipeIsCaughtByTheLatestCheckpoint
// (verify/checkpoint_head_test.go) through the handler.
func TestVerifyRunReportsATotalWipeInsteadOfRefusing(t *testing.T) {
	streamID := id.NewStreamID()

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer := checkpoint.NewEd25519Signer(hmacKeyProvider{key: priv, keyID: "cp-1"})

	cp := &checkpoint.Checkpoint{
		ID: id.NewCheckpointID(), StreamID: streamID, AppID: "app-1",
		FromSeq: 1, ToSeq: 5, ToHash: "hash-at-5", EventCount: 5,
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	cp.SignedPayload = checkpoint.CanonicalPayload(cp)
	sig, keyID, alg, err := signer.Sign(context.Background(), []byte(cp.SignedPayload))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	cp.Signature, cp.SignKeyID, cp.Algorithm = sig, keyID, alg

	s := &verifySpanStore{st: &stream.Stream{
		ID: streamID, AppID: "app-1",
		HeadSeq: 0, HeadHash: "", // wiped: every event gone, head zeroed
	}}
	deps := Deps{
		Store:            s,
		CheckpointStore:  wipeCheckpointStore{cp: cp},
		CheckpointSigner: signer,
	}

	out, err := verifyRunHandler(deps)(context.Background(), VerifyInput{}, principalWith(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("verify.run on a wiped chain returned an error instead of a report: %v", err)
	}
	if out.Report == nil {
		t.Fatal("expected a report for a wiped chain, got nil")
	}
	if out.Report.Valid {
		t.Errorf("a wiped chain whose checkpoint still asserts 5 events reported valid: %+v", out.Report)
	}
	if !out.Report.CheckpointHeadChecked {
		t.Errorf("checkpointHeadChecked must be true: the comparison against the claimed (zero) head ran: %+v", out.Report)
	}
	if out.Report.CheckpointHeadOK {
		t.Errorf("checkpointHeadOk must be false: the checkpoint asserts ToSeq 5 against a claimed head of 0: %+v", out.Report)
	}
	if s.eventRange == 0 {
		t.Error("VerifyChain never ran; a span of 0 must still reach the store")
	}
}

// wipeCheckpointStore answers LatestCheckpoint with a fixed checkpoint,
// simulating a stream whose events and head row are gone but whose signed
// checkpoint still remembers where the chain stood.
type wipeCheckpointStore struct {
	stubCheckpointStore
	cp *checkpoint.Checkpoint
}

func (s wipeCheckpointStore) LatestCheckpoint(context.Context, id.ID) (*checkpoint.Checkpoint, error) {
	return s.cp, nil
}

// A downgraded event -- one claiming a
// weaker scheme than its stream pins at that sequence -- must be reported in
// Downgrades with the report invalid. This also kills a "pin taken from the
// request" mutation: VerifyInput carries no pin, and a zero hash.Pin
// disables downgrade detection entirely (hash.Chain.VerifyWithPin's
// atOrAbovePin is false whenever pin.Scheme == ""), so if the handler ever
// stopped building Pin from the stream row, this test would see the event
// pass as an ordinary weaker-scheme success instead.
func TestVerifyRunFlagsADowngradedEvent(t *testing.T) {
	downgraded := &audit.Event{
		ID: id.NewAuditID(), Sequence: 1, AppID: "app-1",
		HashScheme: string(hash.SchemePlainV4), // claims plain
		Hash:       "irrelevant-downgrade-short-circuits-the-digest-check",
	}
	s := &verifySpanStore{
		st: &stream.Stream{
			ID: id.NewStreamID(), AppID: "app-1",
			HeadSeq: 1, HeadHash: "",
			Scheme: string(hash.SchemeHMACV5), SchemeSince: 1, // stream pins keyed from seq 1
		},
		events: []*audit.Event{downgraded},
	}

	out, err := verifyRunHandler(Deps{Store: s})(context.Background(), VerifyInput{}, principalWith(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("verify.run: %v", err)
	}
	if out.Report == nil || out.Report.Valid {
		t.Fatalf("a downgraded event reported valid: %+v", out.Report)
	}
	var sawDowngrade bool
	for _, seq := range out.Report.Downgrades {
		if seq == 1 {
			sawDowngrade = true
		}
	}
	if !sawDowngrade {
		t.Fatalf("downgrades = %v, want sequence 1 listed", out.Report.Downgrades)
	}
}

// A span exactly at the cap must run.
// (The "one over" half already exists as
// TestVerifyRunRefusesZeroZeroOnAChainLongerThanTheCap, whose head is
// maxVerifySpan+1 -- exactly one sequence past this boundary.)
func TestVerifyRunVerifiesASpanExactlyAtTheCap(t *testing.T) {
	s := &verifySpanStore{st: &stream.Stream{
		ID: id.NewStreamID(), AppID: "app-1",
		HeadSeq: maxVerifySpan, HeadHash: "head-hash",
		Scheme: string(hash.SchemePlainV4), SchemeSince: 1,
	}}

	out, err := verifyRunHandler(Deps{Store: s})(context.Background(), VerifyInput{}, principalWith(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("a span exactly at the cap was refused: %v", err)
	}
	if out.Report == nil {
		t.Fatal("expected a report for a span exactly at the cap")
	}
	if s.eventRange == 0 {
		t.Error("VerifyChain never touched the store for a span exactly at the cap")
	}
}

// verifyEventCallStore counts calls to Get and GetStreamByScope so a test can
// prove Chronicle.VerifyEvent -- which reaches both, through the adapter --
// was never invoked.
type verifyEventCallStore struct {
	store.Store
	getCalls   int
	scopeCalls int
}

func (s *verifyEventCallStore) Get(ctx context.Context, eventID id.ID) (*audit.Event, error) {
	s.getCalls++
	return s.Store.Get(ctx, eventID)
}

func (s *verifyEventCallStore) GetStreamByScope(ctx context.Context, appID, tenantID string) (*stream.Stream, error) {
	s.scopeCalls++
	return s.Store.GetStreamByScope(ctx, appID, tenantID)
}

// An event must not be verifiable by ID alone any more than it is
// readable by ID alone. Fetching another tenant's event by ID must answer
// CodeNotFound and must never reach Chronicle.VerifyEvent -- proved here by
// scopeCalls staying at zero, since VerifyEvent always resolves the event's
// stream through GetStreamByScope.
func TestVerifyEventRefusesAnotherTenantsEvent(t *testing.T) {
	base := newSQLiteStore(t)
	spy := &verifyEventCallStore{Store: base}
	c, err := chronicle.New(chronicle.WithStore(store.NewAdapter(spy)))
	if err != nil {
		t.Fatalf("chronicle.New: %v", err)
	}

	ctx := context.Background()
	other := &audit.Event{AppID: "app-1", TenantID: "tenant-b", Action: "a", Resource: "r", Category: "c"}
	if err := c.Record(ctx, other); err != nil {
		t.Fatalf("seed another tenant's event: %v", err)
	}

	// Reset counters: seeding above already touched both through Record's own
	// stream resolution, and only the handler's own calls matter here.
	spy.getCalls, spy.scopeCalls = 0, 0

	deps := Deps{Store: spy, Chronicle: c}
	viewer := principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"})

	_, err = verifyEventHandler(deps)(ctx, VerifyEventInput{EventID: other.ID.String()}, viewer)

	var ce *fcontract.Error
	if !errors.As(err, &ce) || ce.Code != fcontract.CodeNotFound {
		t.Fatalf("err = %v, want NOT_FOUND", err)
	}
	if spy.getCalls != 1 {
		t.Fatalf("handler's own fetch ran %d time(s), want 1", spy.getCalls)
	}
	if spy.scopeCalls != 0 {
		t.Fatalf("GetStreamByScope ran %d time(s); Chronicle.VerifyEvent must never run for a record outside scope", spy.scopeCalls)
	}
}

// fixedEventStore answers Get with a fixed event, whatever ID was asked for.
// It exists so a test can supply an owned event without a real backend.
type fixedEventStore struct {
	stubStore
	event *audit.Event
}

func (s *fixedEventStore) Get(context.Context, id.ID) (*audit.Event, error) {
	return s.event, nil
}

// A nil deps.Chronicle answers CodeUnavailable, even for an event
// the viewer legitimately owns.
func TestVerifyEventAnswersUnavailableWithNoChronicle(t *testing.T) {
	event := &audit.Event{ID: id.NewAuditID(), AppID: "app-1", TenantID: "tenant-a", HashScheme: string(hash.SchemePlainV4)}
	deps := Deps{Store: &fixedEventStore{event: event}}
	viewer := principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"})

	_, err := verifyEventHandler(deps)(context.Background(), VerifyEventInput{EventID: event.ID.String()}, viewer)
	if !errors.Is(err, fcontract.ErrUnavailable) {
		t.Fatalf("err = %v, want UNAVAILABLE", err)
	}
}

// An ID that does not even parse cannot name a real event. It must answer
// the same NOT_FOUND as a real miss, not a different error that would tell a
// prober the ID's shape was wrong.
func TestVerifyEventAnswersNotFoundForAnUnparseableID(t *testing.T) {
	h := verifyEventHandler(Deps{Store: newStubStore()})
	_, err := h(context.Background(), VerifyEventInput{EventID: "not-a-real-id"}, principalWith(map[string]any{"app_id": "app-1"}))
	if !errors.Is(err, fcontract.ErrNotFound) {
		t.Fatalf("err = %v, want NOT_FOUND", err)
	}
}

// verifyEventScopeMismatchStore answers Get with a fixed event and
// GetStreamByScope with a fixed stream, whatever scope was asked for -- a
// stand-in for a backend whose scope key collides (store/redis builds its
// key as appID + ":" + tenantID, so distinct scopes can land on the same
// row).
type verifyEventScopeMismatchStore struct {
	stubStore
	event  *audit.Event
	stream *stream.Stream
}

func (s *verifyEventScopeMismatchStore) Get(context.Context, id.ID) (*audit.Event, error) {
	return s.event, nil
}

func (s *verifyEventScopeMismatchStore) GetStreamByScope(context.Context, string, string) (*stream.Stream, error) {
	return s.stream, nil
}

// verifyEventNeverCalledStore fails any call, so a test wiring it as the
// backing store of a real *chronicle.Chronicle can prove VerifyEvent (which
// always reaches Get and GetStreamByScope through the adapter) was never
// invoked.
type verifyEventNeverCalledStore struct {
	stubStore
	called int
}

func (s *verifyEventNeverCalledStore) Get(context.Context, id.ID) (*audit.Event, error) {
	s.called++
	return nil, chronicle.ErrEventNotFound
}

func (s *verifyEventNeverCalledStore) GetStreamByScope(context.Context, string, string) (*stream.Stream, error) {
	s.called++
	return nil, chronicle.ErrStreamNotFound
}

// Chronicle.VerifyEvent resolves the event's stream with a raw
// GetStreamByScope(event.AppID, event.TenantID) that carries none of
// scopedStream's collision guard. Handed the wrong stream by a backend whose
// scope key collides, VerifyEvent checks the event against the wrong pin,
// and a downgraded event could come back valid:true. The handler must
// refuse before ever calling VerifyEvent when its own scopedStream
// resolution for the event's scope does not land on the event's own stream
// ID.
func TestVerifyEventRefusesAScopeCollisionToAnotherStream(t *testing.T) {
	event := &audit.Event{
		ID: id.NewAuditID(), AppID: "app-1", TenantID: "tenant-a",
		StreamID: id.NewStreamID(), HashScheme: string(hash.SchemePlainV4),
	}
	// The resolved stream matches the requested scope's fields (so
	// scopedStream's own AppID/TenantID guard does not catch it) but carries
	// a different ID than the event actually claims -- the collision case.
	wrongStream := &stream.Stream{ID: id.NewStreamID(), AppID: "app-1", TenantID: "tenant-a"}
	mismatchStore := &verifyEventScopeMismatchStore{event: event, stream: wrongStream}

	chronicleStore := &verifyEventNeverCalledStore{}
	c, err := chronicle.New(chronicle.WithStore(store.NewAdapter(chronicleStore)))
	if err != nil {
		t.Fatalf("chronicle.New: %v", err)
	}

	deps := Deps{Store: mismatchStore, Chronicle: c}
	viewer := principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"})

	_, err = verifyEventHandler(deps)(context.Background(), VerifyEventInput{EventID: event.ID.String()}, viewer)

	var ce *fcontract.Error
	if !errors.As(err, &ce) || ce.Code != fcontract.CodeInternal {
		t.Fatalf("err = %v, want INTERNAL", err)
	}
	if chronicleStore.called != 0 {
		t.Fatalf("Chronicle.VerifyEvent's own store calls ran %d time(s); it must never run on a resolved scope collision", chronicleStore.called)
	}
}

// hmacKeyProvider is a keys.Provider backed by a fixed 32-byte key, enough to
// drive a real chronicle.Chronicle under SchemeHMACV5 in a test.
type hmacKeyProvider struct {
	key   []byte
	keyID string
}

func (p hmacKeyProvider) Current(context.Context, keys.Use) ([]byte, string, error) {
	return p.key, p.keyID, nil
}

func (p hmacKeyProvider) ByID(_ context.Context, keyID string) ([]byte, error) {
	if keyID != p.keyID {
		return nil, keys.ErrKeyNotFound
	}
	return p.key, nil
}

// Keyed follows the event's own recorded HashScheme, not the
// stream's current pin or this deployment's current configuration.
func TestVerifyEventKeyedFollowsTheEventsScheme(t *testing.T) {
	ctx := context.Background()
	viewer := principalWith(map[string]any{"app_id": "app-1"})

	t.Run("plain", func(t *testing.T) {
		s := newSQLiteStore(t)
		c, err := chronicle.New(chronicle.WithStore(store.NewAdapter(s)))
		if err != nil {
			t.Fatalf("chronicle.New: %v", err)
		}
		event := &audit.Event{AppID: "app-1", Action: "a", Resource: "r", Category: "c"}
		if err := c.Record(ctx, event); err != nil {
			t.Fatalf("record: %v", err)
		}

		out, err := verifyEventHandler(Deps{Store: s, Chronicle: c})(ctx, VerifyEventInput{EventID: event.ID.String()}, viewer)
		if err != nil {
			t.Fatalf("verify.event: %v", err)
		}
		if out.Keyed {
			t.Errorf("plain-scheme event reported keyed")
		}
		if out.HashScheme != string(hash.SchemePlainV4) {
			t.Errorf("hashScheme = %q, want %q", out.HashScheme, hash.SchemePlainV4)
		}
		if !out.Valid {
			t.Errorf("a genuine, untouched event reported invalid: %+v", out)
		}
	})

	t.Run("keyed", func(t *testing.T) {
		// sqlite re-derives the sequence and prev_hash inside its own Append
		// transaction and recomputes the digest under its own (plain) hasher
		// unless it is handed the configured chain via SetHasher, which
		// WithStore's plain adapter does not do. memory persists whatever
		// digest Chronicle computed, which is what this test needs to see.
		s := memory.New()
		provider := hmacKeyProvider{key: make([]byte, keys.HMACKeySize), keyID: "test-key"}
		c, err := chronicle.New(
			chronicle.WithStore(store.NewAdapter(s)),
			chronicle.WithDigestScheme(hash.SchemeHMACV5),
			chronicle.WithKeyProvider(provider),
		)
		if err != nil {
			t.Fatalf("chronicle.New: %v", err)
		}
		event := &audit.Event{AppID: "app-1", Action: "a", Resource: "r", Category: "c"}
		if err := c.Record(ctx, event); err != nil {
			t.Fatalf("record: %v", err)
		}

		deps := Deps{Store: s, Chronicle: c, HashChain: nil}
		out, err := verifyEventHandler(deps)(ctx, VerifyEventInput{EventID: event.ID.String()}, viewer)
		if err != nil {
			t.Fatalf("verify.event: %v", err)
		}
		if !out.Keyed {
			t.Errorf("HMAC-scheme event did not report keyed")
		}
		if out.HashScheme != string(hash.SchemeHMACV5) {
			t.Errorf("hashScheme = %q, want %q", out.HashScheme, hash.SchemeHMACV5)
		}
	})
}

// A real sqlite store and a real *chronicle.Chronicle, so the digests are
// genuine rather than stubbed: verify.run and verify.event both have to
// agree the chain is intact.
func TestVerifyRunAndVerifyEventEndToEndOnSQLite(t *testing.T) {
	ctx := context.Background()
	s := newSQLiteStore(t)
	c, err := chronicle.New(chronicle.WithStore(store.NewAdapter(s)))
	if err != nil {
		t.Fatalf("chronicle.New: %v", err)
	}

	var last *audit.Event
	for i := 0; i < 5; i++ {
		e := &audit.Event{AppID: "app-1", TenantID: "tenant-a", Action: "test.action", Resource: "res", Category: "cat"}
		if err := c.Record(ctx, e); err != nil {
			t.Fatalf("record event %d: %v", i, err)
		}
		last = e
	}

	deps := Deps{Store: s, Chronicle: c}
	viewer := principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"})

	runOut, err := verifyRunHandler(deps)(ctx, VerifyInput{}, viewer)
	if err != nil {
		t.Fatalf("verify.run: %v", err)
	}
	if runOut.Report == nil || !runOut.Report.Valid || runOut.Report.Verified != 5 {
		t.Fatalf("verify.run on a genuine chain = %+v", runOut.Report)
	}

	eventOut, err := verifyEventHandler(deps)(ctx, VerifyEventInput{EventID: last.ID.String()}, viewer)
	if err != nil {
		t.Fatalf("verify.event: %v", err)
	}
	if !eventOut.Valid {
		t.Fatalf("verify.event on a genuine event = %+v", eventOut)
	}
	if eventOut.Keyed {
		t.Fatalf("a plain chain reported keyed: %+v", eventOut)
	}

	// A sibling tenant, seeded in the same store, must see neither.
	otherViewer := principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-z"})
	runOut, err = verifyRunHandler(deps)(ctx, VerifyInput{}, otherViewer)
	if err != nil {
		t.Fatalf("verify.run for a scope with no chain: %v", err)
	}
	if !runOut.NoChain {
		t.Fatalf("verify.run leaked another tenant's chain: %+v", runOut)
	}

	if _, err := verifyEventHandler(deps)(ctx, VerifyEventInput{EventID: last.ID.String()}, otherViewer); !errors.Is(err, fcontract.ErrNotFound) {
		t.Fatalf("verify.event across tenants = %v, want NOT_FOUND", err)
	}
}

// newSQLiteStoreWithRawAccess opens a migrated, file-backed sqlite store the
// same way newSQLiteStore does, but also returns the raw driver so a test
// can rewrite a stored row's content directly through SQL -- bypassing
// every API this package exposes, the way an operator (or attacker) with
// raw database access could, and Chronicle's own hash-chain Append never
// permits.
func newSQLiteStoreWithRawAccess(t *testing.T) (store.Store, *sqlitedriver.SqliteDB) {
	t.Helper()
	ctx := context.Background()

	drv := sqlitedriver.New()
	if err := drv.Open(ctx, filepath.Join(t.TempDir(), "chronicle_contract_tamper.db")); err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db, err := grove.Open(drv)
	if err != nil {
		t.Fatalf("grove.Open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s := sqlite.New(db)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	return s, drv
}

// A real *chronicle.Chronicle over a real sqlite store, so the digests are
// genuine, then a row is rewritten directly through SQL without touching its
// stored hash -- exactly what a rewrite after the fact looks like, since
// nothing about the store's own API lets an attacker "fix" the digest to
// match. verify.run must list the tampered sequence and report invalid;
// verify.event must report that one event invalid and an untouched sibling
// valid.
func TestVerifyDetectsARealChainTamperOnSQLite(t *testing.T) {
	ctx := context.Background()
	s, drv := newSQLiteStoreWithRawAccess(t)
	c, err := chronicle.New(chronicle.WithStore(store.NewAdapter(s)))
	if err != nil {
		t.Fatalf("chronicle.New: %v", err)
	}

	events := make([]*audit.Event, 0, 5)
	for i := 0; i < 5; i++ {
		e := &audit.Event{AppID: "app-1", TenantID: "tenant-a", Action: "action", Resource: "res", Category: "cat"}
		if err := c.Record(ctx, e); err != nil {
			t.Fatalf("record event %d: %v", i, err)
		}
		events = append(events, e)
	}
	tampered := events[2]  // sequence 3
	untouched := events[0] // sequence 1, left alone

	if _, err := drv.Exec(ctx, "UPDATE chronicle_events SET action = ? WHERE id = ?",
		"attacker-rewrote-this", tampered.ID.String()); err != nil {
		t.Fatalf("rewrite stored row: %v", err)
	}

	deps := Deps{Store: s, Chronicle: c}
	viewer := principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"})

	runOut, err := verifyRunHandler(deps)(ctx, VerifyInput{}, viewer)
	if err != nil {
		t.Fatalf("verify.run: %v", err)
	}
	if runOut.Report == nil || runOut.Report.Valid {
		t.Fatalf("verify.run did not detect the rewrite: %+v", runOut.Report)
	}
	var sawTamperedSeq bool
	for _, seq := range runOut.Report.Tampered {
		if seq == tampered.Sequence {
			sawTamperedSeq = true
		}
	}
	if !sawTamperedSeq {
		t.Fatalf("tampered = %v, want sequence %d listed", runOut.Report.Tampered, tampered.Sequence)
	}

	tamperedOut, err := verifyEventHandler(deps)(ctx, VerifyEventInput{EventID: tampered.ID.String()}, viewer)
	if err != nil {
		t.Fatalf("verify.event on the tampered row: %v", err)
	}
	if tamperedOut.Valid {
		t.Fatal("verify.event reported the rewritten event valid")
	}

	cleanOut, err := verifyEventHandler(deps)(ctx, VerifyEventInput{EventID: untouched.ID.String()}, viewer)
	if err != nil {
		t.Fatalf("verify.event on the untouched row: %v", err)
	}
	if !cleanOut.Valid {
		t.Fatal("verify.event reported an untouched event invalid")
	}
}

// ──────────────────────────────────────────────────
// verify.run: retentionPolicies
// ──────────────────────────────────────────────────

// verifyPoliciesFailStore is a real store whose ListPolicies fails, so a
// verification runs for real and only the policy count breaks.
type verifyPoliciesFailStore struct {
	store.Store
}

func (verifyPoliciesFailStore) ListPolicies(context.Context, retention.ListPoliciesOpts) ([]*retention.Policy, error) {
	return nil, errors.New("connection reset")
}

// verifyPolicyCountSpy counts ListPolicies calls on a store that has no
// chain for anyone.
type verifyPolicyCountSpy struct {
	stubStore
	lists int
}

func (s *verifyPolicyCountSpy) ListPolicies(context.Context, retention.ListPoliciesOpts) ([]*retention.Policy, error) {
	s.lists++
	return nil, nil
}

func verifySeedChain(t *testing.T, s store.Store, tenantID string) {
	t.Helper()
	c, err := chronicle.New(chronicle.WithStore(store.NewAdapter(s)))
	if err != nil {
		t.Fatalf("chronicle.New: %v", err)
	}
	for i := 0; i < 3; i++ {
		e := &audit.Event{AppID: "app-1", TenantID: tenantID, Action: "test.action", Resource: "res", Category: "auth"}
		if err := c.Record(context.Background(), e); err != nil {
			t.Fatalf("record event %d: %v", i, err)
		}
	}
}

func verifySavePolicy(t *testing.T, s store.Store, appID, tenantID, category string) {
	t.Helper()
	p := &retention.Policy{
		Entity: chronicle.NewEntity(), ID: id.NewPolicyID(),
		Category: category, Duration: 24 * time.Hour, AppID: appID, TenantID: tenantID,
	}
	if err := s.SavePolicy(context.Background(), p); err != nil {
		t.Fatalf("save policy: %v", err)
	}
}

// Retention purges read as gaps and tampering, and Chronicle cannot yet tell
// them from deletion, so the report says how many policies can purge the
// chain it verified. A chain is one (app, tenant). An app-level policy
// (empty tenant) purges every tenant's chain in its app; a tenant policy
// purges only its own tenant's. So a tenant chain counts its own tenant's
// policies plus the app-level ones, an app-wide chain counts only the
// app-level ones, and sibling-tenant and other-app policies count for
// neither. Counting the viewer's scope instead gets both chains wrong.
func TestVerifyRunCountsThePoliciesThatCanPurgeTheChain(t *testing.T) {
	ctx := context.Background()
	s := newSQLiteStore(t)
	verifySeedChain(t, s, "tenant-a")
	verifySeedChain(t, s, "")
	tenantChain := principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"})
	appChain := principalWith(map[string]any{"app_id": "app-1"})
	h := verifyRunHandler(Deps{Store: s})

	count := func(viewer fcontract.Principal) int {
		t.Helper()
		out, err := h(ctx, VerifyInput{}, viewer)
		if err != nil {
			t.Fatalf("verify.run: %v", err)
		}
		if out.Report == nil || !out.Report.Valid || out.Report.Verified != 3 {
			t.Fatalf("report = %+v, want a valid chain of 3", out.Report)
		}
		return out.Report.RetentionPolicies
	}

	if got := count(tenantChain); got != 0 {
		t.Fatalf("tenant chain with no policies: retentionPolicies = %d, want 0", got)
	}
	if got := count(appChain); got != 0 {
		t.Fatalf("app-wide chain with no policies: retentionPolicies = %d, want 0", got)
	}

	verifySavePolicy(t, s, "app-1", "tenant-a", "auth")    // tenant chain only
	verifySavePolicy(t, s, "app-1", "tenant-a", "billing") // tenant chain only
	verifySavePolicy(t, s, "app-1", "", "auth")            // both chains
	verifySavePolicy(t, s, "app-1", "tenant-b", "auth")    // neither
	verifySavePolicy(t, s, "app-2", "", "auth")            // neither
	verifySavePolicy(t, s, "app-2", "tenant-a", "auth")    // neither

	if got := count(tenantChain); got != 3 {
		t.Fatalf("tenant chain: retentionPolicies = %d, want 3 (two of tenant-a's, one app-level)", got)
	}
	if got := count(appChain); got != 1 {
		t.Fatalf("app-wide chain: retentionPolicies = %d, want 1 (the app-level policy only)", got)
	}
}

// A failure to count policies must not fail the verification: the report
// is still true without the number, which answers -1 for "unknown".
func TestVerifyRunWithAnUncountablePolicyListSaysUnknown(t *testing.T) {
	s := newSQLiteStore(t)
	verifySeedChain(t, s, "tenant-a")

	out, err := verifyRunHandler(Deps{Store: verifyPoliciesFailStore{Store: s}})(context.Background(), VerifyInput{},
		principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"}))
	if err != nil {
		t.Fatalf("verify.run failed because the policy count failed: %v", err)
	}
	if out.Report == nil || out.Report.RetentionPolicies != -1 {
		t.Fatalf("report = %+v, want retentionPolicies -1", out.Report)
	}
	if !out.Report.Valid || out.Report.Verified != 3 {
		t.Fatalf("report = %+v, want the verification itself intact", out.Report)
	}
}

// The count annotates a report, so no report means no count.
func TestVerifyRunWithNoChainDoesNotCountPolicies(t *testing.T) {
	spy := &verifyPolicyCountSpy{stubStore: stubStore{err: chronicle.ErrStreamNotFound}}
	out, err := verifyRunHandler(Deps{Store: spy})(context.Background(), VerifyInput{},
		principalWith(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("verify.run: %v", err)
	}
	if !out.NoChain || spy.lists != 0 {
		t.Fatalf("noChain = %v, ListPolicies calls = %d; want true and 0", out.NoChain, spy.lists)
	}
}
