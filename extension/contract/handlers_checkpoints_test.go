package contract

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	fcontract "github.com/xraph/forge/extensions/dashboard/contract"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/store"
)

// checkpointsFixedStore answers GetCheckpoint with a fixed checkpoint (or
// error), whatever ID was asked for. Every other method falls back to
// stubCheckpointStore's "holds nothing" answers.
type checkpointsFixedStore struct {
	stubCheckpointStore
	cp  *checkpoint.Checkpoint
	err error
}

func (s checkpointsFixedStore) GetCheckpoint(context.Context, id.ID) (*checkpoint.Checkpoint, error) {
	return s.cp, s.err
}

// checkpointStoreWith is a checkpoint.Store whose GetCheckpoint always
// answers cp, whatever ID was asked for.
func checkpointStoreWith(cp *checkpoint.Checkpoint) checkpoint.Store {
	return checkpointsFixedStore{cp: cp}
}

// checkpointsRefusingStore is a checkpoint.Store whose every method answers
// the same fixed error, modelling a backend such as redis that refuses every
// checkpoint call regardless of arguments.
type checkpointsRefusingStore struct{ err error }

var _ checkpoint.Store = checkpointsRefusingStore{}

func (s checkpointsRefusingStore) AppendCheckpoint(context.Context, *checkpoint.Checkpoint) error {
	return s.err
}
func (s checkpointsRefusingStore) LatestCheckpoint(context.Context, id.ID) (*checkpoint.Checkpoint, error) {
	return nil, s.err
}
func (s checkpointsRefusingStore) CheckpointsInRange(context.Context, id.ID, uint64, uint64) ([]*checkpoint.Checkpoint, error) {
	return nil, s.err
}
func (s checkpointsRefusingStore) GetCheckpoint(context.Context, id.ID) (*checkpoint.Checkpoint, error) {
	return nil, s.err
}
func (s checkpointsRefusingStore) ListCheckpoints(context.Context, id.ID, checkpoint.ListOpts) ([]*checkpoint.Checkpoint, error) {
	return nil, s.err
}

// storeRefusingCheckpoints returns a checkpoint.Store whose every method
// answers err, unconditionally, the way store/redis answers
// checkpoint.ErrUnsupported to every call.
func storeRefusingCheckpoints(err error) checkpoint.Store { return checkpointsRefusingStore{err: err} }

// checkpointsCapturingListStore records the ListOpts it was called with, so a
// test can prove the default and cap the handler applies before the store
// ever sees the request.
type checkpointsCapturingListStore struct {
	stubCheckpointStore
	got checkpoint.ListOpts
}

func (s *checkpointsCapturingListStore) ListCheckpoints(_ context.Context, _ id.ID, opts checkpoint.ListOpts) ([]*checkpoint.Checkpoint, error) {
	s.got = opts
	return nil, nil
}

// checkpointsFixedListStore answers ListCheckpoints with a fixed slice,
// whatever ListOpts it was asked for, so a test can drive HasMore's
// extra-row trimming directly.
type checkpointsFixedListStore struct {
	stubCheckpointStore
	cps []*checkpoint.Checkpoint
}

func (s checkpointsFixedListStore) ListCheckpoints(context.Context, id.ID, checkpoint.ListOpts) ([]*checkpoint.Checkpoint, error) {
	return s.cps, nil
}

func fixedCheckpoints(n int) []*checkpoint.Checkpoint {
	out := make([]*checkpoint.Checkpoint, n)
	for i := range out {
		out[i] = &checkpoint.Checkpoint{ID: id.NewCheckpointID()}
	}
	return out
}

// Review Focus 5. Redis implements checkpoint.Store and refuses every call
// with ErrUnsupported. verify treats that as "no opinion" and so must this:
// a backend that holds no checkpoints is a normal deployment, not an error
// page, and the difference from "this chain has none yet" is what Supported
// carries.
func TestCheckpointsListTreatsUnsupportedAsUnsupportedNotAnError(t *testing.T) {
	h := checkpointsListHandler(Deps{
		Store:            newStubStore(),
		CheckpointStore:  storeRefusingCheckpoints(checkpoint.ErrUnsupported),
		CheckpointSigner: stubSigner{},
	})
	out, err := h(context.Background(), CheckpointListInput{}, principalWith(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("an unsupported checkpoint store produced an error: %v", err)
	}
	if out.Supported {
		t.Error("Supported must be false so the page can say 'this backend holds none' rather than 'none yet'")
	}
	if len(out.Checkpoints) != 0 {
		t.Error("expected no checkpoints")
	}
}

// A deployment that never configured checkpointing has no store at all.
// Same answer, different cause, same need to distinguish it from empty.
func TestCheckpointsListWithNoStoreConfigured(t *testing.T) {
	h := checkpointsListHandler(Deps{Store: newStubStore()})
	out, err := h(context.Background(), CheckpointListInput{}, principalWith(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("unconfigured checkpointing produced an error: %v", err)
	}
	if out.Supported {
		t.Error("Supported must be false when this deployment takes no checkpoints")
	}
}

func TestCheckpointsListRefusesBeforeTouchingTheStore(t *testing.T) {
	spy := &checkpointsCapturingListStore{}
	h := checkpointsListHandler(Deps{Store: newStubStore(), CheckpointStore: spy, CheckpointSigner: stubSigner{}})
	if _, err := h(context.Background(), CheckpointListInput{}, principalWith(nil)); !errors.Is(err, fcontract.ErrPermissionDenied) {
		t.Fatalf("err = %v, want PERMISSION_DENIED", err)
	}
	if spy.got != (checkpoint.ListOpts{}) {
		t.Fatalf("handler reached the store before refusing: %+v", spy.got)
	}
}

func TestCheckpointsListRejectsNegativePaging(t *testing.T) {
	h := checkpointsListHandler(Deps{Store: newStubStore(), CheckpointStore: stubCheckpointStore{}, CheckpointSigner: stubSigner{}})
	p := principalWith(map[string]any{"app_id": "app-1"})
	for _, in := range []CheckpointListInput{{Limit: -1}, {Offset: -1}} {
		if _, err := h(context.Background(), in, p); !errors.Is(err, fcontract.ErrBadRequest) {
			t.Fatalf("%+v: err = %v, want BAD_REQUEST", in, err)
		}
	}
}

// Limit 0 defaults to 50, and the store sees limit+1 so HasMore
// can be computed without a total.
func TestCheckpointsListDefaultsTheLimitAndAsksForOneExtraRow(t *testing.T) {
	spy := &checkpointsCapturingListStore{}
	h := checkpointsListHandler(Deps{Store: newSQLiteStore(t), CheckpointStore: spy, CheckpointSigner: stubSigner{}})
	if _, err := h(context.Background(), CheckpointListInput{}, principalWith(map[string]any{"app_id": "app-1"})); err != nil {
		t.Fatalf("checkpoints.list: %v", err)
	}
	if spy.got.Limit != defaultCheckpointListLimit+1 {
		t.Fatalf("store saw limit %d, want %d", spy.got.Limit, defaultCheckpointListLimit+1)
	}
}

// A limit above the maximum is capped, not refused.
func TestCheckpointsListCapsAnOversizedLimit(t *testing.T) {
	spy := &checkpointsCapturingListStore{}
	h := checkpointsListHandler(Deps{Store: newSQLiteStore(t), CheckpointStore: spy, CheckpointSigner: stubSigner{}})
	if _, err := h(context.Background(), CheckpointListInput{Limit: 10_000}, principalWith(map[string]any{"app_id": "app-1"})); err != nil {
		t.Fatalf("checkpoints.list: %v", err)
	}
	if spy.got.Limit != maxCheckpointListLimit+1 {
		t.Fatalf("store saw limit %d, want %d", spy.got.Limit, maxCheckpointListLimit+1)
	}
}

// HasMore is exactly "the store handed back more than the
// requested page", never a stored or computed total.
func TestCheckpointsListComputesHasMoreFromTheExtraRow(t *testing.T) {
	for name, tc := range map[string]struct {
		n        int
		wantLen  int
		wantMore bool
	}{
		"exactly a full page, nothing beyond it": {n: 2, wantLen: 2, wantMore: false},
		"one row past the page":                  {n: 3, wantLen: 2, wantMore: true},
	} {
		t.Run(name, func(t *testing.T) {
			deps := Deps{
				Store:            newStubStore(),
				CheckpointStore:  checkpointsFixedListStore{cps: fixedCheckpoints(tc.n)},
				CheckpointSigner: stubSigner{},
			}
			out, err := checkpointsListHandler(deps)(context.Background(),
				CheckpointListInput{Limit: 2}, principalWith(map[string]any{"app_id": "app-1"}))
			if err != nil {
				t.Fatalf("checkpoints.list: %v", err)
			}
			if len(out.Checkpoints) != tc.wantLen || out.HasMore != tc.wantMore {
				t.Fatalf("got len=%d hasMore=%v, want len=%d hasMore=%v",
					len(out.Checkpoints), out.HasMore, tc.wantLen, tc.wantMore)
			}
			if !out.Supported {
				t.Error("a working store must report Supported true")
			}
		})
	}
}

// checkpointsTouchedStore counts calls to GetCheckpoint, so a test can prove
// a request was refused before it ever reached the store.
type checkpointsTouchedStore struct {
	stubCheckpointStore
	getCheckpointCalls int
}

func (s *checkpointsTouchedStore) GetCheckpoint(context.Context, id.ID) (*checkpoint.Checkpoint, error) {
	s.getCheckpointCalls++
	return nil, checkpoint.ErrNotFound
}

// An ID that does not even parse as a checkpoint ID -- "cp_1" has no valid
// "ckpt_..." suffix -- cannot name a real checkpoint. checkpointsDetailHandler
// must refuse it with the same NOT_FOUND a real miss gets, so a prober
// cannot tell an unparseable ID apart from a real one that just isn't
// theirs, and it must do so before the store is ever touched.
//
// This does NOT exercise v.owns or the ownership boundary: the checkpoint ID
// fails id.ParseCheckpointID before GetCheckpoint or v.owns ever run, which
// is exactly what getCheckpointCalls proves below. It was previously named
// TestCheckpointsDetailRefusesAnotherTenantsCheckpoint and asserted only
// err != nil, which made it read as an ownership test while actually
// covering ID parsing; deleting the owns() check left it passing.
// TestCheckpointsDetailRefusesAnotherTenantsCheckpointByOwnership is the
// test that actually exercises ownership.
func TestCheckpointsDetailRefusesAnUnparseableID(t *testing.T) {
	spy := &checkpointsTouchedStore{}
	h := checkpointsDetailHandler(Deps{
		Store:            newStubStore(),
		CheckpointStore:  spy,
		CheckpointSigner: stubSigner{},
	})
	_, err := h(context.Background(), GetCheckpointInput{ID: "cp_1"},
		principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"}))

	var ce *fcontract.Error
	if !errors.As(err, &ce) || ce.Code != fcontract.CodeNotFound {
		t.Fatalf("err = %v, want NOT_FOUND", err)
	}
	if spy.getCheckpointCalls != 0 {
		t.Fatalf("handler reached the store %d time(s) before refusing an unparseable ID", spy.getCheckpointCalls)
	}
}

// A checkpoint belonging to another tenant, fetched by ID with a
// syntactically valid checkpoint ID, so this actually exercises v.owns
// rather than passing only because the ID fails to parse. The checkpoint's
// StreamID is deliberately set to the viewer's OWN resolved stream, so the
// separate "belongs to the viewer's own stream" check cannot be what catches
// this: only v.owns, comparing the checkpoint's own recorded AppID/TenantID
// against the viewer, can. Removing the owns() check in
// checkpointsDetailHandler must fail this test.
func TestCheckpointsDetailRefusesAnotherTenantsCheckpointByOwnership(t *testing.T) {
	s := newSQLiteStore(t)
	viewersOwnStream := seedStream(t, s, "app-1", "tenant-a")

	// A checkpoint whose recorded scope belongs to a different tenant, but
	// whose StreamID happens to be the viewer's own -- inconsistent data
	// that should never occur in practice, but proves owns() is checked on
	// its own merits rather than being redundant with the stream-ID check.
	cp := &checkpoint.Checkpoint{ID: id.NewCheckpointID(), StreamID: viewersOwnStream.ID, AppID: "app-2", TenantID: "tenant-b"}
	h := checkpointsDetailHandler(Deps{
		Store:            s,
		CheckpointStore:  checkpointStoreWith(cp),
		CheckpointSigner: stubSigner{},
	})
	_, err := h(context.Background(), GetCheckpointInput{ID: cp.ID.String()},
		principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"}))

	var ce *fcontract.Error
	if !errors.As(err, &ce) || ce.Code != fcontract.CodeNotFound {
		t.Fatalf("err = %v, want NOT_FOUND", err)
	}
}

// A checkpoint whose AppID/TenantID match the viewer, but whose StreamID
// does not match the viewer's own resolved stream, must still be refused.
// This is the cheap extra check on top of v.owns.
func TestCheckpointsDetailRefusesACheckpointFromAnotherStreamInTheSameScope(t *testing.T) {
	s := newSQLiteStore(t)
	seedStream(t, s, "app-1", "tenant-a")

	cp := &checkpoint.Checkpoint{
		ID: id.NewCheckpointID(), StreamID: id.NewStreamID(), // NOT own.ID
		AppID: "app-1", TenantID: "tenant-a",
	}
	deps := Deps{
		Store:            s,
		CheckpointStore:  checkpointStoreWith(cp),
		CheckpointSigner: stubSigner{},
	}

	_, err := checkpointsDetailHandler(deps)(context.Background(), GetCheckpointInput{ID: cp.ID.String()},
		principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"}))

	var ce *fcontract.Error
	if !errors.As(err, &ce) || ce.Code != fcontract.CodeNotFound {
		t.Fatalf("err = %v, want NOT_FOUND", err)
	}
}

// ErrUnsupported and ErrNotFound from GetCheckpoint both mean "no such
// checkpoint", the same NOT_FOUND a caller who guessed a real ID would get.
func TestCheckpointsDetailAnswersNotFoundForUnsupportedOrMissing(t *testing.T) {
	for name, cpErr := range map[string]error{
		"unsupported backend": checkpoint.ErrUnsupported,
		"no such checkpoint":  checkpoint.ErrNotFound,
	} {
		t.Run(name, func(t *testing.T) {
			h := checkpointsDetailHandler(Deps{
				Store:            newStubStore(),
				CheckpointStore:  checkpointsFixedStore{err: cpErr},
				CheckpointSigner: stubSigner{},
			})
			_, err := h(context.Background(), GetCheckpointInput{ID: id.NewCheckpointID().String()},
				principalWith(map[string]any{"app_id": "app-1"}))
			var ce *fcontract.Error
			if !errors.As(err, &ce) || ce.Code != fcontract.CodeNotFound {
				t.Fatalf("err = %v, want NOT_FOUND", err)
			}
		})
	}
}

// No store or signer configured: the same NOT_FOUND as a real miss, and no
// nil-pointer call into a CheckpointStore that was never set.
func TestCheckpointsDetailWithNoStoreConfigured(t *testing.T) {
	h := checkpointsDetailHandler(Deps{Store: newStubStore()})
	_, err := h(context.Background(), GetCheckpointInput{ID: id.NewCheckpointID().String()},
		principalWith(map[string]any{"app_id": "app-1"}))
	if !errors.Is(err, fcontract.ErrNotFound) {
		t.Fatalf("err = %v, want NOT_FOUND", err)
	}
}

func TestCheckpointsTakeWithoutACheckpointerIsUnavailable(t *testing.T) {
	h := checkpointsTakeHandler(Deps{Store: newStubStore()})
	_, err := h(context.Background(), TakeCheckpointInput{}, principalWith(map[string]any{"app_id": "app-1"}))
	if err == nil {
		t.Fatal("take succeeded on a deployment that configured no checkpointer")
	}
	if !errors.Is(err, fcontract.ErrUnavailable) {
		t.Fatalf("err = %v, want UNAVAILABLE", err)
	}
}

// A scope with no chain yet has nothing to checkpoint.
func TestCheckpointsTakeOnAScopeWithNoChainIsNotFound(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer := checkpoint.NewEd25519Signer(hmacKeyProvider{key: priv, keyID: "cp-1"})
	checkpointer := checkpoint.NewCheckpointer(stubCheckpointStore{}, signer, nil)

	h := checkpointsTakeHandler(Deps{Store: storeReturning(chronicle.ErrStreamNotFound), Checkpointer: checkpointer})
	_, err = h(context.Background(), TakeCheckpointInput{}, principalWith(map[string]any{"app_id": "app-1"}))
	var ce *fcontract.Error
	if !errors.As(err, &ce) || ce.Code != fcontract.CodeNotFound {
		t.Fatalf("err = %v, want NOT_FOUND", err)
	}
}

// checkpointsExistsStore behaves like an empty checkpoint.Store for reads
// (nothing recorded yet, so CheckpointStream computes fromSeq 1) but refuses
// every AppendCheckpoint with ErrExists, simulating a concurrent
// checkpointer that already won the race for this exact window.
type checkpointsExistsStore struct{ stubCheckpointStore }

func (checkpointsExistsStore) AppendCheckpoint(context.Context, *checkpoint.Checkpoint) error {
	return checkpoint.ErrExists
}

// A concurrent checkpointer winning the race
// must come back as UpToDate true, not CodeInternal. Routing this through
// deps.mapStoreError instead must fail this test.
func TestCheckpointsTakeTreatsALostRaceAsUpToDate(t *testing.T) {
	ctx := context.Background()
	s := newSQLiteStore(t)
	c, err := chronicle.New(chronicle.WithStore(store.NewAdapter(s)))
	if err != nil {
		t.Fatalf("chronicle.New: %v", err)
	}
	event := &audit.Event{AppID: "app-1", Action: "a", Resource: "r", Category: "c"}
	if err := c.Record(ctx, event); err != nil {
		t.Fatalf("record: %v", err)
	}

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer := checkpoint.NewEd25519Signer(hmacKeyProvider{key: priv, keyID: "cp-1"})
	checkpointer := checkpoint.NewCheckpointer(checkpointsExistsStore{}, signer, nil)

	deps := Deps{Store: s, Checkpointer: checkpointer}
	out, err := checkpointsTakeHandler(deps)(ctx, TakeCheckpointInput{}, principalWith(map[string]any{"app_id": "app-1"}))
	if err != nil {
		t.Fatalf("checkpoints.take lost a race and still returned an error: %v", err)
	}
	if !out.UpToDate || out.Checkpoint != nil {
		t.Fatalf("got %+v, want UpToDate true with no checkpoint", out)
	}
}

// A real chain, a real signer, and a real store: take a checkpoint, list it,
// fetch its detail, then take again with nothing new recorded and confirm
// that comes back as an ordinary no-op rather than an error. This is the
// mutation proof for "mapping ErrNothingToCheckpoint through mapStoreError":
// if that mapping regresses, the second take below returns CodeInternal and
// this test fails.
func TestCheckpointsTakeListAndDetailEndToEndOnSQLite(t *testing.T) {
	ctx := context.Background()
	s := newSQLiteStore(t)
	c, err := chronicle.New(chronicle.WithStore(store.NewAdapter(s)))
	if err != nil {
		t.Fatalf("chronicle.New: %v", err)
	}
	for i := 0; i < 3; i++ {
		e := &audit.Event{AppID: "app-1", TenantID: "tenant-a", Action: "action", Resource: "res", Category: "cat"}
		if err := c.Record(ctx, e); err != nil {
			t.Fatalf("record event %d: %v", i, err)
		}
	}

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer := checkpoint.NewEd25519Signer(hmacKeyProvider{key: priv, keyID: "cp-1"})
	checkpointer := checkpoint.NewCheckpointer(s, signer, nil)

	deps := Deps{Store: s, Checkpointer: checkpointer, CheckpointStore: s, CheckpointSigner: signer}
	viewer := principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"})

	takeOut, err := checkpointsTakeHandler(deps)(ctx, TakeCheckpointInput{}, viewer)
	if err != nil {
		t.Fatalf("checkpoints.take: %v", err)
	}
	if takeOut.UpToDate || takeOut.Checkpoint == nil {
		t.Fatalf("first checkpoint over a chain with new events: got %+v", takeOut)
	}
	if takeOut.Checkpoint.FromSeq != 1 || takeOut.Checkpoint.ToSeq != 3 || takeOut.Checkpoint.EventCount != 3 {
		t.Fatalf("checkpoint span = %+v, want [1,3]/3", takeOut.Checkpoint)
	}

	listOut, err := checkpointsListHandler(deps)(ctx, CheckpointListInput{}, viewer)
	if err != nil {
		t.Fatalf("checkpoints.list: %v", err)
	}
	if !listOut.Supported || len(listOut.Checkpoints) != 1 || listOut.Checkpoints[0].ID != takeOut.Checkpoint.ID {
		t.Fatalf("checkpoints.list = %+v, want exactly the checkpoint just taken", listOut)
	}
	if listOut.HasMore {
		t.Fatalf("checkpoints.list reported HasMore with only one checkpoint on the chain: %+v", listOut)
	}

	detailOut, err := checkpointsDetailHandler(deps)(ctx, GetCheckpointInput{ID: takeOut.Checkpoint.ID}, viewer)
	if err != nil {
		t.Fatalf("checkpoints.detail: %v", err)
	}
	if detailOut.Checkpoint != *takeOut.Checkpoint {
		t.Fatalf("checkpoints.detail = %+v, want %+v", detailOut.Checkpoint, *takeOut.Checkpoint)
	}

	// A sibling tenant must see none of this.
	other := principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-z"})
	if _, err := checkpointsDetailHandler(deps)(ctx, GetCheckpointInput{ID: takeOut.Checkpoint.ID}, other); !errors.Is(err, fcontract.ErrNotFound) {
		t.Fatalf("another tenant fetched this checkpoint by ID: err = %v, want NOT_FOUND", err)
	}

	// Taking again with nothing new recorded is a no-op, not an
	// error.
	again, err := checkpointsTakeHandler(deps)(ctx, TakeCheckpointInput{}, viewer)
	if err != nil {
		t.Fatalf("checkpoints.take with nothing new to checkpoint returned an error instead of UpToDate: %v", err)
	}
	if !again.UpToDate || again.Checkpoint != nil {
		t.Fatalf("repeat checkpoints.take = %+v, want UpToDate true with no checkpoint", again)
	}
}

// A client iterates checkpoints, so no answer may carry null for the list:
// not for a backend that refuses every call, and not for a deployment that
// takes no checkpoints at all. Supported says why it is empty.
func TestCheckpointsListNeverAnswersNullForTheList(t *testing.T) {
	cases := map[string]Deps{
		"unsupported backend": {
			Store:            newStubStore(),
			CheckpointStore:  storeRefusingCheckpoints(checkpoint.ErrUnsupported),
			CheckpointSigner: stubSigner{},
		},
		"no store configured": {Store: newStubStore()},
	}
	for name, deps := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := checkpointsListHandler(deps)(context.Background(), CheckpointListInput{}, principalWith(map[string]any{"app_id": "app-1"}))
			if err != nil {
				t.Fatalf("checkpoints.list: %v", err)
			}
			raw, err := json.Marshal(out)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !strings.Contains(string(raw), `"checkpoints":[]`) {
				t.Fatalf("checkpoints was not an empty array: %s", raw)
			}
			if out.Supported {
				t.Fatalf("Supported must stay false: %s", raw)
			}
		})
	}
}

// checkpointsTwoTenantFixture records three events in each of two sibling
// tenants, takes one checkpoint over each chain, and returns the deps plus
// both checkpoints and both chains' IDs, so a test can compare what the wire
// says a checkpoint's owner is against the chain it was actually taken over.
func checkpointsTwoTenantFixture(t *testing.T) (deps Deps, own, foreign *CheckpointSummary, ownStream, foreignStream string) {
	t.Helper()
	ctx := context.Background()
	s := newSQLiteStore(t)
	c, err := chronicle.New(chronicle.WithStore(store.NewAdapter(s)))
	if err != nil {
		t.Fatalf("chronicle.New: %v", err)
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		for i := 0; i < 3; i++ {
			e := &audit.Event{AppID: "app-1", TenantID: tenant, Action: "action", Resource: "res", Category: "cat"}
			if recErr := c.Record(ctx, e); recErr != nil {
				t.Fatalf("record %s event %d: %v", tenant, i, recErr)
			}
		}
	}

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer := checkpoint.NewEd25519Signer(hmacKeyProvider{key: priv, keyID: "cp-1"})
	deps = Deps{Store: s, Checkpointer: checkpoint.NewCheckpointer(s, signer, nil), CheckpointStore: s, CheckpointSigner: signer}

	take := func(tenant string) (*CheckpointSummary, string) {
		out, err := checkpointsTakeHandler(deps)(ctx, TakeCheckpointInput{},
			principalWith(map[string]any{"app_id": "app-1", "tenant_id": tenant}))
		if err != nil || out.Checkpoint == nil {
			t.Fatalf("checkpoints.take for %s: out=%+v err=%v", tenant, out, err)
		}
		st, err := s.GetStreamByScope(ctx, "app-1", tenant)
		if err != nil {
			t.Fatalf("GetStreamByScope %s: %v", tenant, err)
		}
		return out.Checkpoint, st.ID.String()
	}
	own, ownStream = take("tenant-a")
	foreign, foreignStream = take("tenant-b")
	if ownStream == foreignStream {
		t.Fatalf("both tenants resolved to the same chain %s", ownStream)
	}
	return deps, own, foreign, ownStream, foreignStream
}

// The dashboard links a checkpoint to /chain/<streamId>/<from>/<to>, so every
// projection must name the chain the checkpoint was taken over, taken from
// the record itself. Before streamId existed the plugin had to guess the
// owner from streams.list, which fails once that list is truncated.
func TestCheckpointSummaryCarriesItsOwnStreamID(t *testing.T) {
	ctx := context.Background()
	deps, own, _, ownStream, _ := checkpointsTwoTenantFixture(t)
	viewer := principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"})

	if own.StreamID != ownStream {
		t.Errorf("checkpoints.take streamId = %q, want %q", own.StreamID, ownStream)
	}

	detail, err := checkpointsDetailHandler(deps)(ctx, GetCheckpointInput{ID: own.ID}, viewer)
	if err != nil {
		t.Fatalf("checkpoints.detail: %v", err)
	}
	if detail.Checkpoint.StreamID != ownStream {
		t.Errorf("checkpoints.detail streamId = %q, want %q", detail.Checkpoint.StreamID, ownStream)
	}

	list, err := checkpointsListHandler(deps)(ctx, CheckpointListInput{}, viewer)
	if err != nil {
		t.Fatalf("checkpoints.list: %v", err)
	}
	if len(list.Checkpoints) != 1 {
		t.Fatalf("checkpoints.list returned %d checkpoints, want 1", len(list.Checkpoints))
	}
	if got := list.Checkpoints[0].StreamID; got != ownStream {
		t.Errorf("checkpoints.list streamId = %q, want %q", got, ownStream)
	}

	mine, err := streamsMineHandler(deps)(ctx, MineInput{}, viewer)
	if err != nil {
		t.Fatalf("streams.mine: %v", err)
	}
	if mine.Stream == nil || mine.Stream.LatestCheckpoint == nil {
		t.Fatalf("streams.mine = %+v, want a latest checkpoint", mine.Stream)
	}
	if got := mine.Stream.LatestCheckpoint.StreamID; got != ownStream {
		t.Errorf("streams.mine latestCheckpoint.streamId = %q, want %q", got, ownStream)
	}

	// The key on the wire is what the React plugin reads, so pin it.
	raw, err := json.Marshal(detail)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"streamId":"`+ownStream+`"`) {
		t.Errorf("checkpoints.detail JSON = %s, want a streamId key naming %s", raw, ownStream)
	}
}

// Adding streamId must not turn the detail intent into a way to learn which
// chain a foreign checkpoint belongs to. A sibling tenant's checkpoint, asked
// for by its real ID, still answers the same NOT_FOUND as a miss, and the
// answer carries no checkpoint at all.
func TestCheckpointsDetailStillHidesAForeignCheckpoint(t *testing.T) {
	deps, _, foreign, _, foreignStream := checkpointsTwoTenantFixture(t)
	viewer := principalWith(map[string]any{"app_id": "app-1", "tenant_id": "tenant-a"})

	out, err := checkpointsDetailHandler(deps)(context.Background(), GetCheckpointInput{ID: foreign.ID}, viewer)
	if !errors.Is(err, fcontract.ErrNotFound) {
		t.Fatalf("tenant-a fetched tenant-b's checkpoint: err = %v, want NOT_FOUND", err)
	}
	if out.Checkpoint != (CheckpointSummary{}) {
		t.Fatalf("NOT_FOUND answer still carried a checkpoint: %+v", out.Checkpoint)
	}
	if strings.Contains(err.Error(), foreignStream) {
		t.Fatalf("NOT_FOUND error names the foreign chain: %v", err)
	}
}
