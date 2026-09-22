package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/stream"
)

func seedStreamFor(t *testing.T, s *Store, streamID id.ID) {
	t.Helper()
	// Pre-seed rather than letting Chronicle create it: GetStreamByScope cannot
	// return ErrStreamNotFound on this backend yet, so resolveStream's
	// auto-create path is unreachable. Unrelated bug, fixed separately.
	if err := s.CreateStream(context.Background(), &stream.Stream{
		ID: streamID, AppID: "app", TenantID: "tenant",
		Scheme: "chronicle/v2", SchemeSince: 1,
	}); err != nil {
		t.Fatalf("CreateStream: %v", err)
	}
}

func newCP(streamID id.ID, from, to uint64, prev string) *checkpoint.Checkpoint {
	cp := &checkpoint.Checkpoint{
		ID: id.NewCheckpointID(), StreamID: streamID,
		AppID: "app", TenantID: "tenant",
		FromSeq: from, ToSeq: to, FromHash: "from", ToHash: "to",
		EventCount: int64(to - from + 1), PrevCheckpoint: prev,
		Algorithm: checkpoint.AlgorithmEd25519, SignKeyID: "cp-1",
		Signature: []byte{0x01, 0x02, 0x03},
		CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
	}
	cp.SignedPayload = checkpoint.CanonicalPayload(cp)
	return cp
}

func TestCheckpointRoundTripsThroughSQLite(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	streamID := id.NewStreamID()
	seedStreamFor(t, s, streamID)

	cp := newCP(streamID, 1, 100, "prevdigest")
	if err := s.AppendCheckpoint(ctx, cp); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}

	got, err := s.GetCheckpoint(ctx, cp.ID)
	if err != nil {
		t.Fatalf("GetCheckpoint: %v", err)
	}
	if got.SignedPayload != cp.SignedPayload {
		t.Errorf("SignedPayload = %q, want %q", got.SignedPayload, cp.SignedPayload)
	}
	if string(got.Signature) != string(cp.Signature) {
		t.Errorf("Signature = %v, want %v", got.Signature, cp.Signature)
	}
	if got.PrevCheckpoint != "prevdigest" {
		t.Errorf("PrevCheckpoint = %q, want prevdigest", got.PrevCheckpoint)
	}
	if got.EventCount != 100 || got.FromSeq != 1 || got.ToSeq != 100 {
		t.Errorf("range fields lost: %+v", got)
	}
}

// The database is the backstop against two checkpointers racing.
func TestSQLiteRejectsADuplicateCheckpointSequence(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	streamID := id.NewStreamID()
	seedStreamFor(t, s, streamID)

	if err := s.AppendCheckpoint(ctx, newCP(streamID, 1, 100, "")); err != nil {
		t.Fatalf("first AppendCheckpoint: %v", err)
	}
	err := s.AppendCheckpoint(ctx, newCP(streamID, 1, 100, ""))
	if !errors.Is(err, checkpoint.ErrExists) {
		t.Fatalf("second AppendCheckpoint error = %v, want ErrCheckpointExists", err)
	}
}

func TestSQLiteCheckpointsInRangeOverlaps(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	streamID := id.NewStreamID()
	seedStreamFor(t, s, streamID)

	for _, r := range [][2]uint64{{1, 100}, {101, 200}, {201, 300}} {
		if err := s.AppendCheckpoint(ctx, newCP(streamID, r[0], r[1], "")); err != nil {
			t.Fatalf("AppendCheckpoint: %v", err)
		}
	}

	got, err := s.CheckpointsInRange(ctx, streamID, 150, 160)
	if err != nil {
		t.Fatalf("CheckpointsInRange: %v", err)
	}
	if len(got) != 1 || got[0].ToSeq != 200 {
		t.Fatalf("got %d, want the checkpoint covering 101-200", len(got))
	}

	latest, err := s.LatestCheckpoint(ctx, streamID)
	if err != nil {
		t.Fatalf("LatestCheckpoint: %v", err)
	}
	if latest.ToSeq != 300 {
		t.Errorf("latest ToSeq = %d, want 300", latest.ToSeq)
	}
}

// A missing checkpoint must map to checkpoint.ErrNotFound, not a raw driver
// error: notFoundOnNoRows has to recognize whichever no-rows sentinel this
// backend's single-row Scan actually returns.
func TestSQLiteCheckpointNotFound(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	streamID := id.NewStreamID()
	seedStreamFor(t, s, streamID)

	if _, err := s.GetCheckpoint(ctx, id.NewCheckpointID()); !errors.Is(err, checkpoint.ErrNotFound) {
		t.Fatalf("GetCheckpoint on a missing id error = %v, want ErrNotFound", err)
	}

	if _, err := s.LatestCheckpoint(ctx, streamID); !errors.Is(err, checkpoint.ErrNotFound) {
		t.Fatalf("LatestCheckpoint on a stream with no checkpoints error = %v, want ErrNotFound", err)
	}
}
