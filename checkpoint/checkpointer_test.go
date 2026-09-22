package checkpoint_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/id"
)

// fakeStores is the smallest thing satisfying what a Checkpointer reads.
//
// It still tracks events (used by seed to derive HeadHash for the
// StreamHead it hands back), even though nothing here implements
// EventReader any more: CheckpointStream stopped reading events entirely,
// see checkpointer.go.
type fakeStores struct {
	mu     sync.Mutex
	events []*audit.Event
	cps    []*checkpoint.Checkpoint
}

// AppendCheckpoint models what every real backend enforces structurally:
// UNIQUE(stream_id, to_seq) AND UNIQUE(stream_id, from_seq). Both, because
// to_seq alone only arbitrates racers that read the same head -- see
// TestConcurrentCheckpointersReadingDifferentHeadsProduceOne.
func (f *fakeStores) AppendCheckpoint(_ context.Context, cp *checkpoint.Checkpoint) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, existing := range f.cps {
		if existing.StreamID != cp.StreamID {
			continue
		}
		if existing.ToSeq == cp.ToSeq || existing.FromSeq == cp.FromSeq {
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

// n is a parameter because every call site reads as "seed this many events"
// rather than a magic literal, matching how the tests below narrate the
// setup they build on.
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
	return checkpoint.NewCheckpointer(f, signer, nil)
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
// background ticker and an operator-triggered run, each with its OWN
// Checkpointer instance (separate processes, or a ticker's Checkpointer next
// to a handler's), racing on the same stream. Four separate instances here,
// not four goroutines sharing one, is the point: a single Checkpointer's
// per-stream mutex only ever contends with itself, so it cannot be what
// arbitrates this race. What decides it is the shared store's uniqueness
// check, the stand-in here for a real UNIQUE(stream_id, to_seq) constraint.
// Exactly one instance's AppendCheckpoint wins; the rest see ErrExists (if
// they read the head before the winner wrote) or ErrNothingToCheckpoint (if
// they read after).
func TestConcurrentCheckpointersProduceExactlyOne(t *testing.T) {
	ctx := context.Background()
	f := &fakeStores{}
	st := seed(f, id.NewStreamID(), 10)

	checkpointers := make([]*checkpoint.Checkpointer, 4)
	for i := range checkpointers {
		checkpointers[i] = newCheckpointer(t, f)
	}

	var wg sync.WaitGroup
	results := make([]error, 4)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, results[i] = checkpointers[i].CheckpointStream(ctx, st)
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

// TestCreatedAtRoundTripsBackendPrecision is the direct proof for the review
// defect against Task 6: CanonicalPayload renders CreatedAt via
// time.RFC3339Nano, but no real backend stores nanoseconds back losslessly --
// Postgres's TIMESTAMPTZ keeps microseconds and Mongo's BSON keeps
// milliseconds. A CreatedAt signed at full, unrounded resolution comes back
// truncated on those backends, so a verifier's recomputation of
// CanonicalPayload from the read-back row mismatches what was actually
// signed, on a checkpoint nobody touched.
func TestCreatedAtRoundTripsBackendPrecision(t *testing.T) {
	ctx := context.Background()
	signer, _ := newSigner(t, false)

	// This first subtest shows the defect directly, independent of whether
	// CheckpointStream itself still has the bug: it hand-builds a checkpoint
	// the way CheckpointStream used to, at time.Now's native nanosecond
	// resolution -- this is the reviewer's own worked example, reproduced
	// exactly (...123456789 signed, ...123456 read back).
	t.Run("nanosecond precision does not survive a Postgres round trip", func(t *testing.T) {
		cp := &checkpoint.Checkpoint{
			ID: id.NewCheckpointID(), StreamID: id.NewStreamID(),
			AppID: "app", FromSeq: 1, ToSeq: 10, ToHash: "head", EventCount: 10,
			CreatedAt: time.Date(2026, 9, 22, 10, 0, 0, 123456789, time.UTC),
		}
		cp.SignedPayload = checkpoint.CanonicalPayload(cp)
		sig, keyID, alg, err := signer.Sign(ctx, []byte(cp.SignedPayload))
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		cp.Signature, cp.SignKeyID, cp.Algorithm = sig, keyID, alg

		// Simulate reading the row back from Postgres: TIMESTAMPTZ keeps
		// microseconds, so the nanosecond remainder is gone.
		readBack := *cp
		readBack.CreatedAt = cp.CreatedAt.Truncate(time.Microsecond)

		if checkpoint.CanonicalPayload(&readBack) == cp.SignedPayload {
			t.Fatal("expected the nanosecond-precision payload to fail to round-trip through microsecond " +
				"truncation; if this now passes, Postgres's driver or column type changed and this test's " +
				"premise needs revisiting")
		}
		// A verifier comparing CanonicalPayload(&readBack) against
		// cp.SignedPayload would, on this mismatch, wrongly report the row
		// as edited after signing -- exactly the false positive the review
		// found, reproduced here without going anywhere near a database.
	})

	// This second subtest proves the fix: CheckpointStream now truncates
	// CreatedAt to millisecond at creation, which is exactly representable
	// in both Postgres's microseconds and Mongo's milliseconds, so the round
	// trip through either is lossless.
	t.Run("millisecond-truncated CreatedAt survives Postgres and Mongo precision", func(t *testing.T) {
		f := &fakeStores{}
		st := seed(f, id.NewStreamID(), 10)
		cp, err := checkpoint.NewCheckpointer(f, signer, nil).CheckpointStream(ctx, st)
		if err != nil {
			t.Fatalf("CheckpointStream: %v", err)
		}

		postgres := *cp
		postgres.CreatedAt = cp.CreatedAt.Truncate(time.Microsecond)
		if checkpoint.CanonicalPayload(&postgres) != cp.SignedPayload {
			t.Errorf("CreatedAt did not survive a simulated Postgres (microsecond) round trip: %v vs %v",
				postgres.CreatedAt, cp.CreatedAt)
		}

		mongo := *cp
		mongo.CreatedAt = cp.CreatedAt.Truncate(time.Millisecond)
		if checkpoint.CanonicalPayload(&mongo) != cp.SignedPayload {
			t.Errorf("CreatedAt did not survive a simulated Mongo (millisecond) round trip: %v vs %v",
				mongo.CreatedAt, cp.CreatedAt)
		}
	})
}

// staleReadStore holds one checkpointer inside the window between its
// LatestCheckpoint read and its AppendCheckpoint.
//
// That window is the whole problem: CheckpointStream reads the latest
// checkpoint, derives from_seq from it, signs, and inserts, with no
// transaction spanning the two and a per-Checkpointer lock that only ever
// covers one process. Blocking there is what makes the interleaving
// deterministic instead of hoping the scheduler produces it.
type staleReadStore struct {
	*fakeStores
	readDone chan struct{}
	resume   chan struct{}
	once     sync.Once
}

func (s *staleReadStore) LatestCheckpoint(ctx context.Context, streamID id.ID) (*checkpoint.Checkpoint, error) {
	cp, err := s.fakeStores.LatestCheckpoint(ctx, streamID)
	s.once.Do(func() { close(s.readDone) })
	<-s.resume
	return cp, err
}

// TestConcurrentCheckpointersReadingDifferentHeadsProduceOne is the sibling
// TestConcurrentCheckpointersProduceExactlyOne needed and did not have.
//
// That test races four checkpointers that all read the same head, which is
// the one case UNIQUE(stream_id, to_seq) already decides on its own. Two
// replicas on a busy stream routinely do not read the same head: each
// snapshots the stream list at the top of its own tick and then iterates,
// so their views differ by a tick's length. Replica A commits 6-10 while
// replica B, whose LatestCheckpoint read predated A's insert, is still about
// to commit 6-15. Under to_seq alone both succeed, and verification of a
// chain nobody touched then reports the overlapping checkpoint as a
// continuity break -- forever, because checkpoints are append-only and the
// overlap can only be removed by the direct database surgery the feature
// exists to detect.
//
// UNIQUE(stream_id, from_seq) is what decides it: both racers derive the
// same from_seq from the same stale latest checkpoint, so the loser gets
// ErrExists, which checkpointAllStreams already treats as an ordinary
// outcome.
func TestConcurrentCheckpointersReadingDifferentHeadsProduceOne(t *testing.T) {
	ctx := context.Background()
	f := &fakeStores{}
	streamID := id.NewStreamID()
	st := seed(f, streamID, 5)

	// The checkpoint both replicas will read as "latest": 1-5.
	first, err := newCheckpointer(t, f).CheckpointStream(ctx, st)
	if err != nil {
		t.Fatalf("first CheckpointStream: %v", err)
	}
	if first.FromSeq != 1 || first.ToSeq != 5 {
		t.Fatalf("first checkpoint covers %d-%d, want 1-5", first.FromSeq, first.ToSeq)
	}

	stale := &staleReadStore{
		fakeStores: f,
		readDone:   make(chan struct{}),
		resume:     make(chan struct{}),
	}
	replicaB := checkpoint.NewCheckpointer(stale, mustSigner(t), nil)

	// Replica B saw the stream at head 15, a tick later than replica A's
	// snapshot, and reads the latest checkpoint before A commits anything.
	bErr := make(chan error, 1)
	go func() {
		headB := st
		headB.HeadSeq, headB.HeadHash = 15, "hash-o"
		_, cpErr := replicaB.CheckpointStream(ctx, headB)
		bErr <- cpErr
	}()
	<-stale.readDone

	// Replica A, on the same stale latest but an older head, commits 6-10.
	headA := st
	headA.HeadSeq, headA.HeadHash = 10, "hash-j"
	second, err := newCheckpointer(t, f).CheckpointStream(ctx, headA)
	if err != nil {
		t.Fatalf("replica A CheckpointStream: %v", err)
	}
	if second.FromSeq != 6 || second.ToSeq != 10 {
		t.Fatalf("replica A wrote %d-%d, want 6-10", second.FromSeq, second.ToSeq)
	}

	close(stale.resume)
	if bResult := <-bErr; !errors.Is(bResult, checkpoint.ErrExists) {
		t.Fatalf("replica B's overlapping checkpoint returned %v, want ErrExists. A checkpoint "+
			"overlapping one already stored cannot be withdrawn, and it makes an untouched chain "+
			"report tampered from then on", bResult)
	}

	if len(f.cps) != 2 {
		t.Fatalf("%d checkpoints stored, want 2 (1-5 and 6-10): %+v", len(f.cps), f.cps)
	}
	for i, a := range f.cps {
		for _, b := range f.cps[i+1:] {
			if a.FromSeq <= b.ToSeq && b.FromSeq <= a.ToSeq {
				t.Errorf("checkpoints %d-%d and %d-%d overlap", a.FromSeq, a.ToSeq, b.FromSeq, b.ToSeq)
			}
		}
	}
}

// mustSigner returns the same signer newCheckpointer builds, for the one
// test that needs to hand a Checkpointer a store of its own.
func mustSigner(t *testing.T) checkpoint.Signer {
	t.Helper()
	signer, _ := newSigner(t, false) // from signer_test.go, same package
	return signer
}
