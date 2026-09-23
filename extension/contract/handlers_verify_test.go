package contract

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/keys"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
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
type verifySpanStore struct {
	stubStore
	st         *stream.Stream
	eventRange int
	gaps       int
}

func (s *verifySpanStore) GetStreamByScope(context.Context, string, string) (*stream.Stream, error) {
	return s.st, nil
}

func (s *verifySpanStore) EventRange(context.Context, id.ID, uint64, uint64) ([]*audit.Event, error) {
	s.eventRange++
	return nil, nil
}

func (s *verifySpanStore) Gaps(context.Context, id.ID, uint64, uint64) ([]uint64, error) {
	s.gaps++
	return nil, nil
}

func (s *verifySpanStore) touched() int { return s.eventRange + s.gaps }

// RULING 1: a bounded request whose resolved span is under the cap must
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

// RULING 1: a span over the cap must be refused before VerifyChain runs at
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

// RULING 1: fromSeq 0, toSeq 0 -- "verify everything" -- against a chain
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

// RULING 1: a reversed range is refused after resolution, before it can
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

// RULING 1: Deps.MaxVerifySpan overrides the package default; zero means
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

// RULING 2: an event must not be verifiable by ID alone any more than it is
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

// RULING 2: a nil deps.Chronicle answers CodeUnavailable, even for an event
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

// RULING 2: Keyed follows the event's own recorded HashScheme, not the
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
