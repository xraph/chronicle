package contract

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"

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
type streamsTouchedStore struct {
	stubStore
	calls int
}

func (s *streamsTouchedStore) GetStreamByScope(context.Context, string, string) (*stream.Stream, error) {
	s.calls++
	return nil, chronicle.ErrStreamNotFound
}

func (s *streamsTouchedStore) ListStreams(context.Context, stream.ListOpts) ([]*stream.Stream, error) {
	s.calls++
	return nil, nil
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
	st := &stream.Stream{
		Entity:   chronicle.NewEntity(),
		ID:       id.NewStreamID(),
		AppID:    appID,
		TenantID: tenantID,
		HeadHash: "head-" + appID + "-" + tenantID,
		HeadSeq:  7,
		Scheme:   string(hash.SchemePlainV4),
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
	if s.calls != 0 {
		t.Fatalf("handler reached the store %d time(s) before refusing", s.calls)
	}
}

func TestStreamsMineRefusesAnUnreadableTenant(t *testing.T) {
	s := &streamsTouchedStore{}
	h := streamsMineHandler(Deps{Store: s})
	_, err := h(context.Background(), MineInput{}, principalWith(map[string]any{"app_id": "app-1", "tenant_id": 42}))
	if !errors.Is(err, fcontract.ErrPermissionDenied) {
		t.Fatalf("handler served an unreadable tenant claim: err = %v", err)
	}
	if s.calls != 0 {
		t.Fatalf("handler reached the store %d time(s) before refusing", s.calls)
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
// viewer's chains. The foreign chains outnumber one scan batch so the scan
// has to cross a batch boundary to find all of the viewer's.
func TestStreamsListStaysInsideTheViewersApp(t *testing.T) {
	s := newSQLiteStore(t)
	for i := range streamScanBatch + 5 {
		seedStream(t, s, "app-2", fmt.Sprintf("tenant-%03d", i))
	}
	own := map[string]bool{}
	for _, tenant := range []string{"", "tenant-a", "tenant-b"} {
		own[seedStream(t, s, "app-1", tenant).ID.String()] = true
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

	// A tenant viewer sees its own chain and the app-level one, which owns
	// treats as belonging to every operator in the app, and not its sibling
	// tenant's.
	out, err = h(context.Background(), StreamListInput{}, principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"}))
	if err != nil {
		t.Fatalf("streams.list as tenant-a: %v", err)
	}
	if out.Total != 2 {
		t.Fatalf("tenant-a list total = %d, want 2", out.Total)
	}
	for _, st := range out.Streams {
		if st.TenantID == "tenant-b" || st.AppID != "app-1" {
			t.Fatalf("tenant-a saw %s/%s", st.AppID, st.TenantID)
		}
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
	if s.calls != 0 {
		t.Fatalf("handler reached the store %d time(s) before refusing", s.calls)
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

// The default deployment: a plain chain and no checkpoints. The ceiling has
// to say unkeyed, because that is the level at which verification detects
// corruption but not deliberate alteration.
func TestCoverageCeilingIsUnkeyedForADefaultDeployment(t *testing.T) {
	got := coverageCeiling(Deps{}, &stream.Stream{Scheme: string(hash.SchemePlainV4)})
	if got != string(verify.LevelUnkeyed) {
		t.Fatalf("ceiling = %q, want unkeyed", got)
	}
}

func TestCoverageCeilingIsKeyedWithoutCheckpoints(t *testing.T) {
	got := coverageCeiling(Deps{}, &stream.Stream{Scheme: string(hash.SchemeHMACV5)})
	if got != string(verify.LevelKeyed) {
		t.Fatalf("ceiling = %q, want keyed", got)
	}
}

func TestCoverageCeilingNeverReachesAnchored(t *testing.T) {
	// Nothing emits LevelAnchored. A ceiling that claimed it would be
	// promising external anchoring this deployment does not have.
	got := coverageCeiling(Deps{
		CheckpointStore:  stubCheckpointStore{},
		CheckpointSigner: stubSigner{},
	}, &stream.Stream{Scheme: string(hash.SchemeHMACV5)})
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
	got := coverageCeiling(Deps{
		CheckpointStore:  stubCheckpointStore{},
		CheckpointSigner: stubSigner{},
	}, &stream.Stream{Scheme: string(hash.SchemePlainV4)})
	if got != string(verify.LevelSigned) {
		t.Fatalf("ceiling = %q, want signed", got)
	}
}

// A checkpoint store with no signer authenticates nothing, so it must not
// lift the ceiling.
func TestCoverageCeilingIgnoresACheckpointStoreWithoutASigner(t *testing.T) {
	got := coverageCeiling(Deps{CheckpointStore: stubCheckpointStore{}}, &stream.Stream{Scheme: string(hash.SchemeHMACV5)})
	if got != string(verify.LevelKeyed) {
		t.Fatalf("ceiling = %q, want keyed", got)
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

	got, err := projectStream(context.Background(), deps, st)
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
			got, err := projectStream(context.Background(), deps, &stream.Stream{ID: id.NewStreamID(), AppID: "app-1"})
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
	_, err := projectStream(context.Background(), deps, &stream.Stream{ID: id.NewStreamID(), AppID: "app-1"})
	var ce *fcontract.Error
	if !errors.As(err, &ce) || ce.Code != fcontract.CodeInternal || strings.Contains(ce.Error(), "mongo") {
		t.Fatalf("err = %v, want a generic CodeInternal", err)
	}
}

func TestMapStoreError(t *testing.T) {
	for _, sentinel := range notFoundSentinels {
		wrapped := fmt.Errorf("sqlite: select from secret_table: %w", sentinel)
		var ce *fcontract.Error
		if err := mapStoreError(wrapped); !errors.As(err, &ce) || ce.Code != fcontract.CodeNotFound {
			t.Errorf("%v mapped to %v, want NOT_FOUND", sentinel, err)
		} else if strings.Contains(ce.Error(), "secret_table") {
			t.Errorf("NOT_FOUND for %v leaks the wrapper text: %q", sentinel, ce.Error())
		}
	}

	if err := mapStoreError(context.Canceled); !errors.Is(err, fcontract.ErrUnavailable) {
		t.Errorf("context.Canceled mapped to %v, want UNAVAILABLE", err)
	}

	own := &fcontract.Error{Code: fcontract.CodePermissionDenied, Message: "no app scope on this session"}
	if err := mapStoreError(own); err != own { //nolint:errorlint // identity is the point: it must come back untouched
		t.Errorf("a contract error was rewritten to %v", err)
	}

	if mapStoreError(nil) != nil {
		t.Error("mapStoreError(nil) is not nil")
	}
}
