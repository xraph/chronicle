package checkpoint_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/id"
)

// fakeStores is the smallest thing satisfying what a Checkpointer reads.
type fakeStores struct {
	mu     sync.Mutex
	events []*audit.Event
	cps    []*checkpoint.Checkpoint
}

func (f *fakeStores) EventRange(_ context.Context, _ id.ID, from, to uint64) ([]*audit.Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*audit.Event
	for _, e := range f.events {
		if e.Sequence >= from && e.Sequence <= to {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeStores) Gaps(context.Context, id.ID, uint64, uint64) ([]uint64, error) { return nil, nil }

func (f *fakeStores) AppendCheckpoint(_ context.Context, cp *checkpoint.Checkpoint) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, existing := range f.cps {
		if existing.StreamID == cp.StreamID && existing.ToSeq == cp.ToSeq {
			return checkpoint.ErrExists
		}
	}
	f.cps = append(f.cps, cp)
	return nil
}

func (f *fakeStores) LatestCheckpoint(_ context.Context, streamID id.ID) (*checkpoint.Checkpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var latest *checkpoint.Checkpoint
	for _, cp := range f.cps {
		if cp.StreamID == streamID && (latest == nil || cp.ToSeq > latest.ToSeq) {
			latest = cp
		}
	}
	if latest == nil {
		return nil, checkpoint.ErrNotFound
	}
	return latest, nil
}

func (f *fakeStores) CheckpointsInRange(context.Context, id.ID, uint64, uint64) ([]*checkpoint.Checkpoint, error) {
	return nil, nil
}
func (f *fakeStores) GetCheckpoint(context.Context, id.ID) (*checkpoint.Checkpoint, error) {
	return nil, checkpoint.ErrNotFound
}
func (f *fakeStores) ListCheckpoints(context.Context, id.ID, checkpoint.ListOpts) ([]*checkpoint.Checkpoint, error) {
	return nil, nil
}

// n is always 10 today; kept as a parameter because every call site reads
// as "seed 10 events" rather than a magic literal, matching how the tests
// below narrate the setup they build on.
//
//nolint:unparam // n kept general on purpose, see comment above.
func seed(f *fakeStores, streamID id.ID, n uint64) checkpoint.StreamHead {
	for i := uint64(1); i <= n; i++ {
		f.events = append(f.events, &audit.Event{
			Sequence: i, StreamID: streamID,
			Hash: "hash-" + string(rune('a'+i)), Action: "a", Resource: "r", Category: "c",
		})
	}
	return checkpoint.StreamHead{
		ID: streamID, AppID: "app", TenantID: "tenant",
		HeadSeq: n, HeadHash: f.events[n-1].Hash,
	}
}

func newCheckpointer(t *testing.T, f *fakeStores) *checkpoint.Checkpointer {
	t.Helper()
	signer, _ := newSigner(t, false) // from signer_test.go, same package
	return checkpoint.NewCheckpointer(f, f, signer, nil)
}

func TestCheckpointStreamSignsTheHeadState(t *testing.T) {
	ctx := context.Background()
	f := &fakeStores{}
	st := seed(f, id.NewStreamID(), 10)

	cp, err := newCheckpointer(t, f).CheckpointStream(ctx, st)
	if err != nil {
		t.Fatalf("CheckpointStream: %v", err)
	}
	if cp.FromSeq != 1 || cp.ToSeq != 10 {
		t.Errorf("range = %d..%d, want 1..10", cp.FromSeq, cp.ToSeq)
	}
	if cp.ToHash != st.HeadHash {
		t.Errorf("ToHash = %q, want the stream head %q", cp.ToHash, st.HeadHash)
	}
	if cp.EventCount != 10 {
		t.Errorf("EventCount = %d, want 10", cp.EventCount)
	}
	if cp.PrevCheckpoint != "" {
		t.Error("a stream's first checkpoint must have an empty PrevCheckpoint")
	}
	if len(cp.Signature) == 0 || cp.SignKeyID == "" || cp.SignedPayload == "" {
		t.Error("checkpoint was stored unsigned")
	}
}

// Continuity is what makes deleting a checkpoint from the middle detectable.
func TestSecondCheckpointChainsToTheFirst(t *testing.T) {
	ctx := context.Background()
	f := &fakeStores{}
	st := seed(f, id.NewStreamID(), 10)
	c := newCheckpointer(t, f)

	first, err := c.CheckpointStream(ctx, st)
	if err != nil {
		t.Fatalf("first CheckpointStream: %v", err)
	}

	// Ten more events arrive.
	for i := uint64(11); i <= 20; i++ {
		f.events = append(f.events, &audit.Event{Sequence: i, StreamID: st.ID, Hash: "h", Action: "a", Resource: "r", Category: "c"})
	}
	st.HeadSeq, st.HeadHash = 20, "h"

	second, err := c.CheckpointStream(ctx, st)
	if err != nil {
		t.Fatalf("second CheckpointStream: %v", err)
	}
	if second.FromSeq != 11 {
		t.Errorf("second FromSeq = %d, want 11 (one past the first's ToSeq)", second.FromSeq)
	}
	if second.PrevCheckpoint != checkpoint.Digest(first.SignedPayload) {
		t.Error("second checkpoint does not chain to the first's signed payload")
	}
}

func TestCheckpointStreamWithNothingNew(t *testing.T) {
	ctx := context.Background()
	f := &fakeStores{}
	st := seed(f, id.NewStreamID(), 10)
	c := newCheckpointer(t, f)

	if _, err := c.CheckpointStream(ctx, st); err != nil {
		t.Fatalf("first CheckpointStream: %v", err)
	}
	if _, err := c.CheckpointStream(ctx, st); !errors.Is(err, checkpoint.ErrNothingToCheckpoint) {
		t.Errorf("second CheckpointStream error = %v, want ErrNothingToCheckpoint", err)
	}
}

// The shape that produced a duplicate-and-panic bug elsewhere in this repo: a
// background ticker and a handler racing. The database uniqueness constraint is
// the backstop, so exactly one wins and the loser reports cleanly.
func TestConcurrentCheckpointersProduceExactlyOne(t *testing.T) {
	ctx := context.Background()
	f := &fakeStores{}
	st := seed(f, id.NewStreamID(), 10)
	c := newCheckpointer(t, f)

	var wg sync.WaitGroup
	results := make([]error, 4)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, results[i] = c.CheckpointStream(ctx, st)
		}(i)
	}
	wg.Wait()

	var created int
	for _, err := range results {
		switch {
		case err == nil:
			created++
		case errors.Is(err, checkpoint.ErrExists), errors.Is(err, checkpoint.ErrNothingToCheckpoint):
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if created != 1 {
		t.Errorf("%d checkpointers created one, want exactly 1", created)
	}
	if len(f.cps) != 1 {
		t.Errorf("%d checkpoints stored, want 1", len(f.cps))
	}
}
