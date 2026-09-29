package contract

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"
	log "github.com/xraph/go-utils/log"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/hash"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
	"github.com/xraph/chronicle/stream"
	"github.com/xraph/chronicle/verify"
)

// streamsTouchedStore records whether a handler reached the store at all. A
// refused principal must be refused before the first store call, not after.
// byScope and lists count the two read paths separately, so a test can also
// prove which path a handler took.
type streamsTouchedStore struct {
	stubStore
	byScope int
	lists   int
}

func (s *streamsTouchedStore) GetStreamByScope(context.Context, string, string) (*stream.Stream, error) {
	s.byScope++
	return nil, chronicle.ErrStreamNotFound
}

func (s *streamsTouchedStore) ListStreams(context.Context, stream.ListOpts) ([]*stream.Stream, error) {
	s.lists++
	return nil, nil
}

func (s *streamsTouchedStore) calls() int { return s.byScope + s.lists }

// streamsWrongScopeStore answers GetStreamByScope with a fixed stream,
// whatever scope was asked for. It models a backend whose scope match is
// wrong, such as store/redis's appID + ":" + tenantID key, where app "a:b"
// with tenant "c" and app "a" with tenant "b:c" share a key.
type streamsWrongScopeStore struct {
	stubStore
	st *stream.Stream
}

func (s *streamsWrongScopeStore) GetStreamByScope(context.Context, string, string) (*stream.Stream, error) {
	return s.st, nil
}

// streamsFixedCheckpointStore answers LatestCheckpoint with a fixed result.
type streamsFixedCheckpointStore struct {
	stubCheckpointStore
	cp  *checkpoint.Checkpoint
	err error
}

func (s streamsFixedCheckpointStore) LatestCheckpoint(context.Context, id.ID) (*checkpoint.Checkpoint, error) {
	return s.cp, s.err
}

// seedStream creates one chain in s for the given scope and returns it.
func seedStream(t *testing.T, s store.Store, appID, tenantID string) *stream.Stream {
	t.Helper()
	return seedStreamAt(t, s, appID, tenantID, time.Now().UTC())
}

// seedStreamAt is seedStream with an explicit creation time. The SQL stores
// list streams newest first, so this is how a test decides which batch of a
// scan a chain lands in.
func seedStreamAt(t *testing.T, s store.Store, appID, tenantID string, created time.Time) *stream.Stream {
	t.Helper()
	st := &stream.Stream{
		Entity:      chronicle.Entity{CreatedAt: created, UpdatedAt: created},
		ID:          id.NewStreamID(),
		AppID:       appID,
		TenantID:    tenantID,
		HeadHash:    "head-" + appID + "-" + tenantID,
		HeadSeq:     7,
		Scheme:      string(hash.SchemePlainV4),
		SchemeSince: 1,
	}
	if err := s.CreateStream(context.Background(), st); err != nil {
		t.Fatalf("create stream %s/%s: %v", appID, tenantID, err)
	}
	return st
}

// A scope with no events yet is a normal state, not an error. Chronicle
// creates a stream on the first Record, so a fresh app has none.
func TestStreamsMineAnswersEmptyForAScopeWithNoChain(t *testing.T) {
	h := streamsMineHandler(Deps{Store: storeReturning(chronicle.ErrStreamNotFound)})
	out, err := h(context.Background(), MineInput{}, principalWith(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("handler returned an error for a scope with no chain: %v", err)
	}
	if out.Stream != nil {
		t.Fatal("expected no stream")
	}
}

// The same "no chain yet" path against a real backend. The stub above only
// proves the handler recognizes ErrStreamNotFound; this proves sqlite's miss
// on GetStreamByScope actually arrives as ErrStreamNotFound, which is what
// the handler depends on.
func TestStreamsMineAnswersEmptyForAScopeWithNoChainOnSQLite(t *testing.T) {
	s := newSQLiteStore(t)
	seedStream(t, s, "app-other", "") // a chain exists, just not this scope's

	h := streamsMineHandler(Deps{Store: s})
	out, err := h(context.Background(), MineInput{}, principalWith(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("handler returned an error for a scope with no chain on sqlite: %v", err)
	}
	if out.Stream != nil {
		t.Fatalf("expected no stream, got %+v", out.Stream)
	}
}

func TestStreamsMineRefusesAPrincipalWithNoApp(t *testing.T) {
	s := &streamsTouchedStore{}
	h := streamsMineHandler(Deps{Store: s})
	_, err := h(context.Background(), MineInput{}, principalWith(nil))
	if !errors.Is(err, fcontract.ErrPermissionDenied) {
		t.Fatalf("handler served a principal with no app scope: err = %v", err)
	}
	if s.calls() != 0 {
		t.Fatalf("handler reached the store %d time(s) before refusing", s.calls())
	}
}

func TestStreamsMineRefusesAnUnreadableTenant(t *testing.T) {
	s := &streamsTouchedStore{}
	h := streamsMineHandler(Deps{Store: s})
	_, err := h(context.Background(), MineInput{}, principalWith(map[string]any{"app_id": "app-1", "tenant_id": 42}))
	if !errors.Is(err, fcontract.ErrPermissionDenied) {
		t.Fatalf("handler served an unreadable tenant claim: err = %v", err)
	}
	if s.calls() != 0 {
		t.Fatalf("handler reached the store %d time(s) before refusing", s.calls())
	}
}

// Each viewer gets exactly their own scope's chain: a tenant viewer gets the
// tenant's, an app-wide viewer the app-level one, and nobody gets another
// app's.
func TestStreamsMineReturnsOnlyTheViewersOwnChain(t *testing.T) {
	s := newSQLiteStore(t)
	appLevel := seedStream(t, s, "app-1", "")
	tenantA := seedStream(t, s, "app-1", "tenant-a")
	seedStream(t, s, "app-1", "tenant-b")
	seedStream(t, s, "app-2", "tenant-a")

	h := streamsMineHandler(Deps{Store: s})
	for name, tc := range map[string]struct {
		claims map[string]any
		want   *stream.Stream
	}{
		"tenant viewer":   {map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"}, tenantA},
		"org_id viewer":   {map[string]any{"app_id": "app-1", "org_id": "tenant-a"}, tenantA},
		"app-wide viewer": {map[string]any{"app_id": "app-1"}, appLevel},
		"another app":     {map[string]any{"app_id": "app-3", "tenant_id": "tenant-a"}, nil},
		"unknown tenant":  {map[string]any{"app_id": "app-1", "tenant_id": "tenant-z"}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := h(context.Background(), MineInput{}, principalWith(tc.claims))
			if err != nil {
				t.Fatalf("streams.mine: %v", err)
			}
			if tc.want == nil {
				if out.Stream != nil {
					t.Fatalf("got %+v, want no stream", out.Stream)
				}
				return
			}
			if out.Stream == nil {
				t.Fatalf("got no stream, want %s", tc.want.ID)
			}
			got := out.Stream
			if got.ID != tc.want.ID.String() || got.AppID != tc.want.AppID || got.TenantID != tc.want.TenantID {
				t.Fatalf("got %s %s/%s, want %s %s/%s",
					got.ID, got.AppID, got.TenantID, tc.want.ID, tc.want.AppID, tc.want.TenantID)
			}
			if got.HeadHash != tc.want.HeadHash || got.HeadSeq != 7 || got.Scheme != string(hash.SchemePlainV4) {
				t.Fatalf("projection lost fields: %+v", got)
			}
			if got.CoverageCeiling != string(verify.LevelUnkeyed) || got.CheckpointingConfigured || got.LatestCheckpoint != nil {
				t.Fatalf("default deployment projected checkpoint state: %+v", got)
			}
		})
	}
}

// streams.mine must refuse a chain the store hands back for the wrong scope
// rather than serve it. This is the only guard against a backend whose
// scope match collides (see streamsWrongScopeStore).
func TestStreamsMineRefusesAChainFromAnotherScope(t *testing.T) {
	for name, tc := range map[string]struct {
		claims map[string]any
		st     *stream.Stream
	}{
		"redis key collision": {
			claims: map[string]any{"app_id": "a", "tenant_id": "b:c"},
			st:     &stream.Stream{ID: id.NewStreamID(), AppID: "a:b", TenantID: "c"},
		},
		"another tenant": {
			claims: map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"},
			st:     &stream.Stream{ID: id.NewStreamID(), AppID: "app-1", TenantID: "tenant-b"},
		},
		"app-wide viewer handed a tenant's chain": {
			claims: map[string]any{"app_id": "app-1"},
			st:     &stream.Stream{ID: id.NewStreamID(), AppID: "app-1", TenantID: "tenant-b"},
		},
		"another app": {
			claims: map[string]any{"app_id": "app-1"},
			st:     &stream.Stream{ID: id.NewStreamID(), AppID: "app-2"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			deps := Deps{Store: &streamsWrongScopeStore{st: tc.st}}

			out, err := streamsMineHandler(deps)(context.Background(), MineInput{}, principalWith(tc.claims))
			if err == nil || out.Stream != nil {
				t.Fatalf("streams.mine served a chain from %s/%s: out=%+v err=%v", tc.st.AppID, tc.st.TenantID, out.Stream, err)
			}
			if !errors.Is(err, fcontract.ErrInternal) {
				t.Fatalf("err = %v, want INTERNAL", err)
			}

			// A tenant viewer's streams.list takes the same path.
			if _, isTenant := tc.claims["tenant_id"]; isTenant {
				list, err := streamsListHandler(deps)(context.Background(), StreamListInput{}, principalWith(tc.claims))
				if err == nil || len(list.Streams) != 0 {
					t.Fatalf("streams.list served a chain from %s/%s: out=%+v err=%v", tc.st.AppID, tc.st.TenantID, list, err)
				}
			}
		})
	}
}

// A store failure must reach the browser as a generic internal error. The
// driver's own text can name tables, hosts and credentials.
func TestStreamsMineDoesNotLeakAStoreError(t *testing.T) {
	leak := "pq: connection to 10.0.0.7 failed for user chronicle password=hunter2 on relation chronicle_streams"
	h := streamsMineHandler(Deps{Store: storeReturning(errors.New(leak))})
	_, err := h(context.Background(), MineInput{}, principalWith(map[string]any{"app_id": "app-1"}))

	var ce *fcontract.Error
	if !errors.As(err, &ce) || ce.Code != fcontract.CodeInternal {
		t.Fatalf("err = %v, want a CodeInternal contract error", err)
	}
	for _, fragment := range []string{"pq:", "10.0.0.7", "hunter2", "chronicle_streams"} {
		if strings.Contains(ce.Error(), fragment) {
			t.Fatalf("contract error %q leaks %q from the store error", ce.Error(), fragment)
		}
	}
}

// streams.list must stay inside the viewer's app however many other apps
// share the store, and its page, total and hasMore must describe only the
// viewer's chains.
//
// The viewer's chains are seeded FIRST, with the oldest timestamps, and then
// more than one full scan batch of other apps' chains. The SQL stores list
// newest first, so the first batch the scan reads holds nothing the viewer
// owns and every one of the viewer's chains sits past it. A scan that
// stopped on a batch with no OWNED rows, rather than no UNSEEN rows, would
// return nothing here.
func TestStreamsListStaysInsideTheViewersApp(t *testing.T) {
	s := newSQLiteStore(t)
	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	own := map[string]bool{}
	for i, tenant := range []string{"", "tenant-a", "tenant-b"} {
		own[seedStreamAt(t, s, "app-1", tenant, old.Add(time.Duration(i)*time.Second)).ID.String()] = true
	}
	recent := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range streamScanBatch + 5 {
		seedStreamAt(t, s, "app-2", fmt.Sprintf("tenant-%04d", i), recent.Add(time.Duration(i)*time.Second))
	}

	h := streamsListHandler(Deps{Store: s})
	out, err := h(context.Background(), StreamListInput{}, principalWith(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("streams.list: %v", err)
	}
	if out.Total != 3 || len(out.Streams) != 3 || out.HasMore {
		t.Fatalf("app-wide list: total=%d len=%d hasMore=%v, want 3/3/false", out.Total, len(out.Streams), out.HasMore)
	}
	for _, st := range out.Streams {
		if st.AppID != "app-1" || !own[st.ID] {
			t.Fatalf("streams.list returned a chain outside app-1: %+v", st)
		}
	}
}

// A tenant viewer owns exactly one chain, its own tenant's, and not the
// app-level one or a sibling tenant's. It is answered through
// GetStreamByScope without scanning ListStreams at all.
func TestStreamsListForATenantViewerIsItsOwnChainOnly(t *testing.T) {
	s := newSQLiteStore(t)
	seedStream(t, s, "app-1", "")
	tenantA := seedStream(t, s, "app-1", "tenant-a")
	seedStream(t, s, "app-1", "tenant-b")
	seedStream(t, s, "app-2", "tenant-a")

	h := streamsListHandler(Deps{Store: s})
	p := principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"})

	out, err := h(context.Background(), StreamListInput{}, p)
	if err != nil {
		t.Fatalf("streams.list as tenant-a: %v", err)
	}
	if out.Total != 1 || len(out.Streams) != 1 || out.HasMore || out.Streams[0].ID != tenantA.ID.String() {
		t.Fatalf("tenant-a list = %+v, want exactly its own chain", out)
	}

	out, err = h(context.Background(), StreamListInput{Offset: 1}, p)
	if err != nil {
		t.Fatalf("streams.list as tenant-a, offset 1: %v", err)
	}
	if out.Total != 1 || len(out.Streams) != 0 || out.HasMore {
		t.Fatalf("tenant-a list at offset 1 = %+v, want an empty page with total 1", out)
	}

	out, err = h(context.Background(), StreamListInput{}, principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-z"}))
	if err != nil {
		t.Fatalf("streams.list as a tenant with no chain: %v", err)
	}
	if out.Total != 0 || len(out.Streams) != 0 || out.HasMore {
		t.Fatalf("tenant with no chain = %+v, want empty", out)
	}

	spy := &streamsTouchedStore{}
	if _, err := streamsListHandler(Deps{Store: spy})(context.Background(), StreamListInput{}, p); err != nil {
		t.Fatalf("streams.list against the spy: %v", err)
	}
	if spy.lists != 0 || spy.byScope != 1 {
		t.Fatalf("tenant viewer read ListStreams %d time(s) and GetStreamByScope %d time(s), want 0 and 1", spy.lists, spy.byScope)
	}
}

func TestStreamsListPagesOverTheViewersChainsOnly(t *testing.T) {
	s := newSQLiteStore(t)
	for i := range 5 {
		seedStream(t, s, "app-1", fmt.Sprintf("tenant-%d", i))
		seedStream(t, s, "app-2", fmt.Sprintf("tenant-%d", i))
	}
	h := streamsListHandler(Deps{Store: s})
	p := principalWith(map[string]any{"app_id": "app-1"})

	seen := map[string]bool{}
	for _, tc := range []struct {
		offset, wantLen int
		wantMore        bool
	}{
		{0, 2, true},
		{2, 2, true},
		{4, 1, false},
		{9, 0, false},
	} {
		out, err := h(context.Background(), StreamListInput{Limit: 2, Offset: tc.offset}, p)
		if err != nil {
			t.Fatalf("offset %d: %v", tc.offset, err)
		}
		if out.Total != 5 || len(out.Streams) != tc.wantLen || out.HasMore != tc.wantMore {
			t.Fatalf("offset %d: total=%d len=%d hasMore=%v, want 5/%d/%v",
				tc.offset, out.Total, len(out.Streams), out.HasMore, tc.wantLen, tc.wantMore)
		}
		for _, st := range out.Streams {
			if seen[st.ID] {
				t.Fatalf("offset %d repeated chain %s", tc.offset, st.ID)
			}
			seen[st.ID] = true
		}
	}
	if len(seen) != 5 {
		t.Fatalf("paging visited %d chains, want 5", len(seen))
	}
}

func TestStreamsListRefusesBeforeTouchingTheStore(t *testing.T) {
	s := &streamsTouchedStore{}
	h := streamsListHandler(Deps{Store: s})
	for name, claims := range map[string]map[string]any{
		"no app":            nil,
		"unreadable tenant": {"app_id": "app-1", "tenant_id": 42},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := h(context.Background(), StreamListInput{}, principalWith(claims)); !errors.Is(err, fcontract.ErrPermissionDenied) {
				t.Fatalf("err = %v, want PERMISSION_DENIED", err)
			}
		})
	}
	if s.calls() != 0 {
		t.Fatalf("handler reached the store %d time(s) before refusing", s.calls())
	}
}

func TestStreamsListRejectsNegativePaging(t *testing.T) {
	h := streamsListHandler(Deps{Store: newStubStore()})
	p := principalWith(map[string]any{"app_id": "app-1"})
	for _, in := range []StreamListInput{{Limit: -1}, {Offset: -1}} {
		if _, err := h(context.Background(), in, p); !errors.Is(err, fcontract.ErrBadRequest) {
			t.Fatalf("%+v: err = %v, want BAD_REQUEST", in, err)
		}
	}
}

// The in-memory store returns every stream again once the offset reaches its
// length, so with exactly one full batch of streams a naive scan would read
// the same full batch forever. The scan must notice nothing new arrived.
func TestStreamsListTerminatesOnAStoreThatIgnoresAnOffsetPastTheEnd(t *testing.T) {
	s := memory.New()
	for i := range streamScanBatch {
		seedStream(t, s, "app-1", fmt.Sprintf("tenant-%03d", i))
	}

	done := make(chan StreamListResponse, 1)
	errc := make(chan error, 1)
	go func() {
		out, err := streamsListHandler(Deps{Store: s})(context.Background(),
			StreamListInput{Limit: 1}, principalWith(map[string]any{"app_id": "app-1"}))
		if err != nil {
			errc <- err
			return
		}
		done <- out
	}()

	select {
	case out := <-done:
		if out.Total != streamScanBatch {
			t.Fatalf("total = %d, want %d", out.Total, streamScanBatch)
		}
	case err := <-errc:
		t.Fatalf("streams.list: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("streams.list did not terminate against the in-memory store")
	}
}

// ceilingStream is a chain with events at and above its pin, so its ceiling
// is decided by scheme and checkpointing rather than by the empty-range cap.
func ceilingStream(scheme hash.Scheme) *stream.Stream {
	return &stream.Stream{Scheme: string(scheme), SchemeSince: 1, HeadSeq: 10}
}

// withCheckpoints is a Deps that holds checkpoints and a signer.
var withCheckpoints = Deps{CheckpointStore: stubCheckpointStore{}, CheckpointSigner: stubSigner{}}

// The default deployment: a plain chain and no checkpoints. The ceiling has
// to say unkeyed, because that is the level at which verification detects
// corruption but not deliberate alteration.
func TestCoverageCeilingIsUnkeyedForADefaultDeployment(t *testing.T) {
	got := coverageCeiling(Deps{}, ceilingStream(hash.SchemePlainV4))
	if got != string(verify.LevelUnkeyed) {
		t.Fatalf("ceiling = %q, want unkeyed", got)
	}
}

func TestCoverageCeilingIsKeyedWithoutCheckpoints(t *testing.T) {
	got := coverageCeiling(Deps{}, ceilingStream(hash.SchemeHMACV5))
	if got != string(verify.LevelKeyed) {
		t.Fatalf("ceiling = %q, want keyed", got)
	}
}

func TestCoverageCeilingNeverReachesAnchored(t *testing.T) {
	// Nothing emits LevelAnchored. A ceiling that claimed it would be
	// promising external anchoring this deployment does not have.
	got := coverageCeiling(withCheckpoints, ceilingStream(hash.SchemeHMACV5))
	if got == string(verify.LevelAnchored) {
		t.Fatal("ceiling claimed anchored")
	}
	if got != string(verify.LevelSigned) {
		t.Fatalf("ceiling = %q, want signed", got)
	}
}

// verify.Verifier raises a checkpointed span to signed whatever the digest
// scheme (verify/checkpoint_test.go's TestIntactCheckpointedChainReportsSigned
// runs on an unkeyed chain), so the ceiling for a checkpointed plain chain is
// signed too. Reporting unkeyed here would put the ceiling below the level
// the verify page then shows.
func TestCoverageCeilingIsSignedForACheckpointedPlainChain(t *testing.T) {
	got := coverageCeiling(withCheckpoints, ceilingStream(hash.SchemePlainV4))
	if got != string(verify.LevelSigned) {
		t.Fatalf("ceiling = %q, want signed", got)
	}
}

// A checkpoint store with no signer authenticates nothing, so it must not
// lift the ceiling.
func TestCoverageCeilingIgnoresACheckpointStoreWithoutASigner(t *testing.T) {
	got := coverageCeiling(Deps{CheckpointStore: stubCheckpointStore{}}, ceilingStream(hash.SchemeHMACV5))
	if got != string(verify.LevelKeyed) {
		t.Fatalf("ceiling = %q, want keyed", got)
	}
}

// When the chain holds no events at or above its pin, verify grades the
// whole range unkeyed (gradeCoverage) and never raises it to signed
// (upgradeSpan), so the ceiling must not promise more, however strong the
// scheme and whatever checkpointing is configured.
func TestCoverageCeilingIsUnkeyedBelowThePin(t *testing.T) {
	for name, st := range map[string]*stream.Stream{
		// A fresh stream: pinned from sequence 1, nothing recorded yet.
		"empty stream": {Scheme: string(hash.SchemeHMACV5), SchemeSince: 1, HeadSeq: 0},
		// An empty stream with no pin at all has nothing to verify either.
		"empty stream, zero pin": {Scheme: string(hash.SchemeHMACV5), SchemeSince: 0, HeadSeq: 0},
		// The pin moved up to 11 and nothing has been appended since.
		"pin moved, no append since": {Scheme: string(hash.SchemeHMACV5), SchemeSince: 11, HeadSeq: 10},
	} {
		t.Run(name, func(t *testing.T) {
			for depsName, deps := range map[string]Deps{"no checkpoints": {}, "checkpoints": withCheckpoints} {
				if got := coverageCeiling(deps, st); got != string(verify.LevelUnkeyed) {
					t.Errorf("%s: ceiling = %q, want unkeyed", depsName, got)
				}
			}
		})
	}

	// The first append at the pin lifts the cap.
	atPin := &stream.Stream{Scheme: string(hash.SchemeHMACV5), SchemeSince: 11, HeadSeq: 11}
	if got := coverageCeiling(withCheckpoints, atPin); got != string(verify.LevelSigned) {
		t.Errorf("head at the pin: ceiling = %q, want signed", got)
	}
}

func TestProjectStreamAttachesTheLatestCheckpoint(t *testing.T) {
	created := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	cp := &checkpoint.Checkpoint{
		ID: id.NewCheckpointID(), FromSeq: 1, ToSeq: 100, EventCount: 100,
		SignKeyID: "cp-key-1", CreatedAt: created,
	}
	deps := Deps{
		CheckpointStore:  streamsFixedCheckpointStore{cp: cp},
		CheckpointSigner: stubSigner{},
	}
	st := &stream.Stream{ID: id.NewStreamID(), AppID: "app-1", Scheme: string(hash.SchemeHMACV5)}

	got, err := projectStream(context.Background(), deps, "streams.mine", st)
	if err != nil {
		t.Fatalf("projectStream: %v", err)
	}
	if !got.CheckpointingConfigured || got.LatestCheckpoint == nil {
		t.Fatalf("checkpoint state not projected: %+v", got)
	}
	want := CheckpointSummary{
		ID: cp.ID.String(), FromSeq: 1, ToSeq: 100, EventCount: 100,
		CreatedAt: "2026-09-23T10:00:00Z", SignKeyID: "cp-key-1",
	}
	if *got.LatestCheckpoint != want {
		t.Fatalf("latest checkpoint = %+v, want %+v", *got.LatestCheckpoint, want)
	}
}

// No checkpoint yet, and a backend that refuses checkpoints, both leave
// LatestCheckpoint nil with CheckpointingConfigured still true.
func TestProjectStreamToleratesNoCheckpointYet(t *testing.T) {
	for name, cpErr := range map[string]error{
		"none yet":    checkpoint.ErrNotFound,
		"unsupported": checkpoint.ErrUnsupported,
	} {
		t.Run(name, func(t *testing.T) {
			deps := Deps{CheckpointStore: streamsFixedCheckpointStore{err: cpErr}, CheckpointSigner: stubSigner{}}
			got, err := projectStream(context.Background(), deps, "streams.mine", &stream.Stream{ID: id.NewStreamID(), AppID: "app-1"})
			if err != nil {
				t.Fatalf("projectStream: %v", err)
			}
			if !got.CheckpointingConfigured || got.LatestCheckpoint != nil {
				t.Fatalf("got %+v, want configured with no checkpoint", got)
			}
		})
	}
}

// Any other checkpoint read failure fails the call. Answering "no checkpoint
// yet" when the truth is "we could not look" would misstate assurance.
func TestProjectStreamFailsOnACheckpointReadError(t *testing.T) {
	deps := Deps{
		CheckpointStore:  streamsFixedCheckpointStore{err: errors.New("mongo: server selection timeout")},
		CheckpointSigner: stubSigner{},
	}
	_, err := projectStream(context.Background(), deps, "streams.mine", &stream.Stream{ID: id.NewStreamID(), AppID: "app-1"})
	var ce *fcontract.Error
	if !errors.As(err, &ce) || ce.Code != fcontract.CodeInternal || strings.Contains(ce.Error(), "mongo") {
		t.Fatalf("err = %v, want a generic CodeInternal", err)
	}
}

func TestMapStoreError(t *testing.T) {
	var d Deps // nil Logger: must fall back to a no-op logger, not panic
	for _, sentinel := range notFoundSentinels {
		wrapped := fmt.Errorf("sqlite: select from secret_table: %w", sentinel)
		var ce *fcontract.Error
		if err := d.mapStoreError("test", wrapped); !errors.As(err, &ce) || ce.Code != fcontract.CodeNotFound {
			t.Errorf("%v mapped to %v, want NOT_FOUND", sentinel, err)
		} else if strings.Contains(ce.Error(), "secret_table") {
			t.Errorf("NOT_FOUND for %v leaks the wrapper text: %q", sentinel, ce.Error())
		}
	}

	if err := d.mapStoreError("test", context.Canceled); !errors.Is(err, fcontract.ErrUnavailable) {
		t.Errorf("context.Canceled mapped to %v, want UNAVAILABLE", err)
	}

	own := &fcontract.Error{Code: fcontract.CodePermissionDenied, Message: "no app scope on this session"}
	if err := d.mapStoreError("test", own); err != own { //nolint:errorlint // identity is the point: it must come back untouched
		t.Errorf("a contract error was rewritten to %v", err)
	}

	if d.mapStoreError("test", nil) != nil {
		t.Error("mapStoreError(nil) is not nil")
	}

	if err := d.mapStoreError("test", errors.New("pq: boom")); !errors.Is(err, fcontract.ErrInternal) {
		t.Errorf("an unknown error with a nil Logger mapped to %v, want INTERNAL", err)
	}
}

// The internal branch is the one place the underlying cause survives, so it
// must reach the log, and must not reach the contract error.
func TestMapStoreErrorLogsTheCauseOfAnInternalError(t *testing.T) {
	logger := log.NewTestLogger()
	d := Deps{Logger: logger}

	cause := errors.New("pq: connection to 10.0.0.7 refused, password=hunter2")
	err := d.mapStoreError("streams.mine", cause)

	var ce *fcontract.Error
	if !errors.As(err, &ce) || ce.Code != fcontract.CodeInternal {
		t.Fatalf("err = %v, want INTERNAL", err)
	}
	if strings.Contains(ce.Error(), "10.0.0.7") || strings.Contains(ce.Error(), "hunter2") {
		t.Fatalf("contract error leaks the cause: %q", ce.Error())
	}

	tl, ok := logger.(*log.TestLogger)
	if !ok {
		t.Fatalf("NewTestLogger returned %T", logger)
	}
	entries := tl.GetLogsByLevel("ERROR")
	if len(entries) != 1 {
		t.Fatalf("logged %d error(s), want 1: %+v", len(entries), tl.GetLogs())
	}
	logged, _ := entries[0].Field("error")
	op, _ := entries[0].Field("op")
	if !strings.Contains(fmt.Sprint(logged), "10.0.0.7") || op != "streams.mine" {
		t.Fatalf("log entry %+v does not carry the cause and op", entries[0])
	}

	// Not-found and cancellation are expected outcomes, not store failures,
	// and are not logged.
	tl.Clear()
	_ = d.mapStoreError("streams.mine", chronicle.ErrStreamNotFound)
	_ = d.mapStoreError("streams.mine", context.Canceled)
	if n := len(tl.GetLogs()); n != 0 {
		t.Fatalf("logged %d entries for expected outcomes, want 0", n)
	}
}

// The op on a log line is the intent that failed, so an operator reading the
// log can find the request. A checkpoint read failing while streams.mine or
// streams.list projects a chain must say which of the two it was.
func TestStreamProjectionLogsTheIntentThatFailed(t *testing.T) {
	for _, intent := range []string{"streams.mine", "streams.list"} {
		t.Run(intent, func(t *testing.T) {
			s := newSQLiteStore(t)
			seedStream(t, s, "app-1", "")
			logger := log.NewTestLogger()
			deps := Deps{
				Store:            s,
				CheckpointStore:  streamsFixedCheckpointStore{err: errors.New("mongo: server selection timeout")},
				CheckpointSigner: stubSigner{},
				Logger:           logger,
			}
			viewer := principalWith(map[string]any{"app_id": "app-1"})

			var err error
			if intent == "streams.mine" {
				_, err = streamsMineHandler(deps)(context.Background(), MineInput{}, viewer)
			} else {
				_, err = streamsListHandler(deps)(context.Background(), StreamListInput{}, viewer)
			}
			if !errors.Is(err, fcontract.ErrInternal) {
				t.Fatalf("err = %v, want INTERNAL", err)
			}

			entries := logger.(*log.TestLogger).GetLogsByLevel("ERROR")
			if len(entries) != 1 {
				t.Fatalf("logged %d error(s), want 1", len(entries))
			}
			if op, _ := entries[0].Field("op"); op != intent {
				t.Fatalf("logged op = %v, want %q", op, intent)
			}
		})
	}
}

// A logger passed through Deps reaches mapStoreError from a real handler.
func TestStreamsMineLogsAStoreFailure(t *testing.T) {
	logger := log.NewTestLogger()
	h := streamsMineHandler(Deps{Store: storeReturning(errors.New("pq: boom")), Logger: logger})
	if _, err := h(context.Background(), MineInput{}, principalWith(map[string]any{"app_id": "app-1"})); !errors.Is(err, fcontract.ErrInternal) {
		t.Fatalf("err = %v, want INTERNAL", err)
	}
	if n := logger.(*log.TestLogger).CountLogs("ERROR"); n != 1 {
		t.Fatalf("logged %d error(s), want 1", n)
	}
}
