package contract

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/stream"
)

// selectorFixture is a real sqlite store holding chains for app-1/tenant-a
// (3 events), app-1/tenant-b (1 event) and app-2/tenant-a (1 event), and no
// app-level chain for app-1. That is the shape an app-wide viewer sees when
// every event was recorded under a tenant.
type selectorFixture struct {
	deps        Deps
	tenantA     *stream.Stream
	tenantB     *stream.Stream
	otherApp    *stream.Stream
	appWide     fcontract.Principal
	tenantAView fcontract.Principal
	tenantBView fcontract.Principal
}

func newSelectorFixture(t *testing.T) selectorFixture {
	t.Helper()
	ctx := context.Background()
	s := newSQLiteStore(t)

	c, err := chronicle.New(chronicle.WithStore(store.NewAdapter(s)))
	if err != nil {
		t.Fatalf("chronicle.New: %v", err)
	}
	record := func(appID, tenantID string, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			e := &audit.Event{AppID: appID, TenantID: tenantID, Action: "act", Resource: "res", Category: "cat"}
			if recordErr := c.Record(ctx, e); recordErr != nil {
				t.Fatalf("record %s/%s: %v", appID, tenantID, recordErr)
			}
		}
	}
	record("app-1", "tenant-a", 3)
	record("app-1", "tenant-b", 1)
	record("app-2", "tenant-a", 1)

	chain := func(appID, tenantID string) *stream.Stream {
		t.Helper()
		st, streamErr := s.GetStreamByScope(ctx, appID, tenantID)
		if streamErr != nil {
			t.Fatalf("stream %s/%s: %v", appID, tenantID, streamErr)
		}
		return st
	}

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer := checkpoint.NewEd25519Signer(hmacKeyProvider{key: priv, keyID: "cp-1"})

	return selectorFixture{
		deps: Deps{
			Store:            s,
			Checkpointer:     checkpoint.NewCheckpointer(s, signer, nil),
			CheckpointStore:  s,
			CheckpointSigner: signer,
		},
		tenantA:     chain("app-1", "tenant-a"),
		tenantB:     chain("app-1", "tenant-b"),
		otherApp:    chain("app-2", "tenant-a"),
		appWide:     principalWith(map[string]any{"app_id": "app-1"}),
		tenantAView: principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"}),
		tenantBView: principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-b"}),
	}
}

// selectorCall is one of the intents that take a streamId, run against a
// chosen streamId and viewer.
type selectorCall struct {
	name string
	call func(deps Deps, streamID string, p fcontract.Principal) error
}

func selectorCalls() []selectorCall {
	ctx := context.Background()
	return []selectorCall{
		{"verify.run", func(deps Deps, sid string, p fcontract.Principal) error {
			_, err := verifyRunHandler(deps)(ctx, VerifyInput{StreamID: sid}, p)
			return err
		}},
		{"checkpoints.list", func(deps Deps, sid string, p fcontract.Principal) error {
			_, err := checkpointsListHandler(deps)(ctx, CheckpointListInput{StreamID: sid}, p)
			return err
		}},
		{"checkpoints.take", func(deps Deps, sid string, p fcontract.Principal) error {
			_, err := checkpointsTakeHandler(deps)(ctx, TakeCheckpointInput{StreamID: sid}, p)
			return err
		}},
		{"streams.mine", func(deps Deps, sid string, p fcontract.Principal) error {
			_, err := streamsMineHandler(deps)(ctx, MineInput{StreamID: sid}, p)
			return err
		}},
	}
}

// An app-wide viewer of an app whose events all sit under tenants has no
// app-level chain, so its own scope answers "no chain" for every intent. Each
// tenant's chain is listed by streams.list, and naming it by ID has to reach
// it: verify it, list its checkpoints, take one, read one back.
func TestAppWideViewerReachesATenantChainByStreamID(t *testing.T) {
	ctx := context.Background()
	f := newSelectorFixture(t)
	sid := f.tenantA.ID.String()

	// Its own scope is empty, and says so.
	own, err := verifyRunHandler(f.deps)(ctx, VerifyInput{}, f.appWide)
	if err != nil || !own.NoChain {
		t.Fatalf("app-wide verify.run with no streamId = %+v, %v; want noChain", own, err)
	}

	// streams.list is how it learns the ID.
	list, err := streamsListHandler(f.deps)(ctx, StreamListInput{}, f.appWide)
	if err != nil {
		t.Fatalf("streams.list: %v", err)
	}
	found := false
	for _, s := range list.Streams {
		if s.ID == sid && s.TenantID == "tenant-a" {
			found = true
		}
	}
	if !found {
		t.Fatalf("streams.list = %+v, want tenant-a's chain %s", list.Streams, sid)
	}

	// streams.mine with the ID.
	mine, err := streamsMineHandler(f.deps)(ctx, MineInput{StreamID: sid}, f.appWide)
	if err != nil || mine.Stream == nil || mine.Stream.ID != sid || mine.Stream.HeadSeq != 3 {
		t.Fatalf("streams.mine by streamId = %+v, %v; want tenant-a's chain at head 3", mine, err)
	}

	// verify.run with the ID.
	ver, err := verifyRunHandler(f.deps)(ctx, VerifyInput{StreamID: sid}, f.appWide)
	if err != nil {
		t.Fatalf("verify.run by streamId: %v", err)
	}
	if ver.NoChain || ver.Report == nil || !ver.Report.Valid || ver.Report.Verified != 3 {
		t.Fatalf("verify.run by streamId = %+v, want a valid chain of 3", ver)
	}

	// checkpoints.take with the ID, then list and detail.
	take, err := checkpointsTakeHandler(f.deps)(ctx, TakeCheckpointInput{StreamID: sid}, f.appWide)
	if err != nil || take.Checkpoint == nil || take.Checkpoint.ToSeq != 3 {
		t.Fatalf("checkpoints.take by streamId = %+v, %v; want a checkpoint to seq 3", take, err)
	}
	cps, err := checkpointsListHandler(f.deps)(ctx, CheckpointListInput{StreamID: sid}, f.appWide)
	if err != nil || !cps.Supported || len(cps.Checkpoints) != 1 || cps.Checkpoints[0].ID != take.Checkpoint.ID {
		t.Fatalf("checkpoints.list by streamId = %+v, %v; want the checkpoint just taken", cps, err)
	}
	// Without the ID the viewer's own scope has no chain, so nothing lists.
	ownCps, err := checkpointsListHandler(f.deps)(ctx, CheckpointListInput{}, f.appWide)
	if err != nil || len(ownCps.Checkpoints) != 0 {
		t.Fatalf("checkpoints.list with no streamId = %+v, %v; want none", ownCps, err)
	}
	if _, takeErr := checkpointsTakeHandler(f.deps)(ctx, TakeCheckpointInput{}, f.appWide); !errors.Is(takeErr, fcontract.ErrNotFound) {
		t.Fatalf("checkpoints.take with no streamId and no app-level chain: err = %v, want NOT_FOUND", takeErr)
	}

	detail, err := checkpointsDetailHandler(f.deps)(ctx, GetCheckpointInput{ID: take.Checkpoint.ID}, f.appWide)
	if err != nil {
		t.Fatalf("checkpoints.detail on a tenant's checkpoint for the app-wide viewer: %v", err)
	}
	if detail.Checkpoint != *take.Checkpoint {
		t.Fatalf("checkpoints.detail = %+v, want %+v", detail.Checkpoint, *take.Checkpoint)
	}
}

// The count of policies that can purge a selected chain is about that chain's
// scope. An app-wide viewer verifying tenant-a's chain must count tenant-a's
// own policies as well as the app-level ones.
func TestVerifyRunByStreamIDCountsPoliciesForTheSelectedChain(t *testing.T) {
	ctx := context.Background()
	f := newSelectorFixture(t)
	verifySavePolicy(t, f.deps.Store, "app-1", "tenant-a", "auth") // purges tenant-a's chain
	verifySavePolicy(t, f.deps.Store, "app-1", "", "auth")         // purges every tenant's chain
	verifySavePolicy(t, f.deps.Store, "app-1", "tenant-b", "auth") // tenant-b's chain only

	out, err := verifyRunHandler(f.deps)(ctx, VerifyInput{StreamID: f.tenantA.ID.String()}, f.appWide)
	if err != nil || out.Report == nil {
		t.Fatalf("verify.run: %+v, %v", out, err)
	}
	if out.Report.RetentionPolicies != 2 {
		t.Fatalf("retentionPolicies = %d, want 2 (tenant-a's and the app-level one)", out.Report.RetentionPolicies)
	}
}

// A streamId is a lookup key and never a grant. A tenant viewer selecting a
// sibling tenant's chain, and an app-wide viewer selecting another app's,
// both get NOT_FOUND from every intent that takes one.
func TestSelectingAChainTheViewerDoesNotOwnIsNotFound(t *testing.T) {
	f := newSelectorFixture(t)

	cases := []struct {
		name     string
		streamID string
		viewer   fcontract.Principal
	}{
		{"tenant-b viewer, tenant-a chain", f.tenantA.ID.String(), f.tenantBView},
		{"tenant-a viewer, tenant-b chain", f.tenantB.ID.String(), f.tenantAView},
		{"app-1 app-wide viewer, app-2 chain", f.otherApp.ID.String(), f.appWide},
	}
	for _, tc := range cases {
		for _, sc := range selectorCalls() {
			t.Run(tc.name+" "+sc.name, func(t *testing.T) {
				if err := sc.call(f.deps, tc.streamID, tc.viewer); !errors.Is(err, fcontract.ErrNotFound) {
					t.Fatalf("err = %v, want NOT_FOUND", err)
				}
			})
		}
	}

	// The refused take must not have signed anything.
	cps, err := f.deps.CheckpointStore.ListCheckpoints(context.Background(), f.tenantA.ID, checkpoint.ListOpts{Limit: 10})
	if err != nil || len(cps) != 0 {
		t.Fatalf("tenant-a's chain holds %d checkpoints (err %v) after refused takes, want 0", len(cps), err)
	}
}

// A tenant viewer can still select its own chain, which is the same chain an
// empty streamId gives it.
func TestATenantViewerMaySelectItsOwnChain(t *testing.T) {
	f := newSelectorFixture(t)
	for _, sc := range selectorCalls() {
		t.Run(sc.name, func(t *testing.T) {
			if err := sc.call(f.deps, f.tenantA.ID.String(), f.tenantAView); err != nil {
				t.Fatalf("err = %v, want success", err)
			}
		})
	}
}

// selectorCountingStore counts GetStream calls, so a test can prove an ID
// that cannot name a chain never reached the store.
type selectorCountingStore struct {
	stubStore
	gets int
}

func (s *selectorCountingStore) GetStream(context.Context, id.ID) (*stream.Stream, error) {
	s.gets++
	return nil, nil
}

func TestSelectingAnUnparseableStreamIDIsNotFoundWithoutTouchingTheStore(t *testing.T) {
	viewer := principalWith(map[string]any{"app_id": "app-1"})
	for name, bad := range map[string]string{
		"garbage":         "not-an-id",
		"wrong prefix":    id.NewAuditID().String(),
		"whitespace only": "  ",
	} {
		for _, sc := range selectorCalls() {
			t.Run(name+" "+sc.name, func(t *testing.T) {
				spy := &selectorCountingStore{}
				deps := Deps{Store: spy, Checkpointer: checkpoint.NewCheckpointer(stubCheckpointStore{}, stubSigner{}, nil),
					CheckpointStore: stubCheckpointStore{}, CheckpointSigner: stubSigner{}}
				if err := sc.call(deps, bad, viewer); !errors.Is(err, fcontract.ErrNotFound) {
					t.Fatalf("err = %v, want NOT_FOUND", err)
				}
				if spy.gets != 0 {
					t.Fatalf("GetStream was called %d times for an ID that cannot parse", spy.gets)
				}
			})
		}
	}
}

// A store that answers a miss with (nil, nil) means the same as
// ErrStreamNotFound, and must not panic.
func TestSelectingAStreamTheStoreAnswersNilForIsNotFound(t *testing.T) {
	viewer := principalWith(map[string]any{"app_id": "app-1"})
	for _, sc := range selectorCalls() {
		t.Run(sc.name, func(t *testing.T) {
			deps := Deps{Store: &selectorCountingStore{}, Checkpointer: checkpoint.NewCheckpointer(stubCheckpointStore{}, stubSigner{}, nil),
				CheckpointStore: stubCheckpointStore{}, CheckpointSigner: stubSigner{}}
			if err := sc.call(deps, id.NewStreamID().String(), viewer); !errors.Is(err, fcontract.ErrNotFound) {
				t.Fatalf("err = %v, want NOT_FOUND", err)
			}
		})
	}
}

// selectorCollidingStore answers GetStream with one chain and
// GetStreamByScope with whatever the test says the scope resolves to, the
// shape of store/redis's scope-key collision.
type selectorCollidingStore struct {
	stubStore
	byID    *stream.Stream
	byScope *stream.Stream
	scopeEr error
}

func (s *selectorCollidingStore) GetStream(context.Context, id.ID) (*stream.Stream, error) {
	return s.byID, nil
}

func (s *selectorCollidingStore) GetStreamByScope(context.Context, string, string) (*stream.Stream, error) {
	return s.byScope, s.scopeEr
}

// The selected chain is re-resolved from its own scope, and refused when that
// lands on a different row or on none, so the redis scope-key collision guard
// stays in force for a chain chosen by ID.
func TestSelectingAChainWhoseScopeResolvesElsewhereIsRefused(t *testing.T) {
	chosen := &stream.Stream{ID: id.NewStreamID(), AppID: "app-1", TenantID: "tenant-a"}
	other := &stream.Stream{ID: id.NewStreamID(), AppID: "app-1", TenantID: "tenant-a"}
	viewer := principalWith(map[string]any{"app_id": "app-1"})

	cases := map[string]*selectorCollidingStore{
		"scope resolves to a different chain": {byID: chosen, byScope: other},
		"scope resolves to no chain":          {byID: chosen, scopeEr: chronicle.ErrStreamNotFound},
	}
	for name, st := range cases {
		for _, sc := range selectorCalls() {
			t.Run(name+" "+sc.name, func(t *testing.T) {
				deps := Deps{Store: st, Checkpointer: checkpoint.NewCheckpointer(stubCheckpointStore{}, stubSigner{}, nil),
					CheckpointStore: stubCheckpointStore{}, CheckpointSigner: stubSigner{}}
				if err := sc.call(deps, chosen.ID.String(), viewer); !errors.Is(err, fcontract.ErrInternal) {
					t.Fatalf("err = %v, want INTERNAL", err)
				}
			})
		}
	}
}
