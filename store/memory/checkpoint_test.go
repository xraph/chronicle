package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/id"
)

// newCP always receives prev="" in this file's tests; the parameter is kept
// because PrevCheckpoint is a real field on Checkpoint and every call site
// here happens to test a stream's first checkpoint.
//
//nolint:unparam // prev kept for symmetry with the Checkpoint field it sets.
func newCP(streamID id.ID, from, to uint64, prev string) *checkpoint.Checkpoint {
	cp := &checkpoint.Checkpoint{
		ID:             id.NewCheckpointID(),
		StreamID:       streamID,
		AppID:          "app",
		TenantID:       "tenant",
		FromSeq:        from,
		ToSeq:          to,
		FromHash:       "from",
		ToHash:         "to",
		EventCount:     int64(to - from + 1),
		PrevCheckpoint: prev,
		Algorithm:      checkpoint.AlgorithmEd25519,
		SignKeyID:      "cp-1",
		Signature:      []byte("sig"),
		CreatedAt:      time.Now().UTC(),
	}
	cp.SignedPayload = checkpoint.CanonicalPayload(cp)
	return cp
}

func TestAppendAndGetCheckpoint(t *testing.T) {
	ctx := context.Background()
	s := New()
	streamID := id.NewStreamID()

	cp := newCP(streamID, 1, 100, "")
	if err := s.AppendCheckpoint(ctx, cp); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}

	got, err := s.GetCheckpoint(ctx, cp.ID)
	if err != nil {
		t.Fatalf("GetCheckpoint: %v", err)
	}
	if got.ToSeq != 100 || got.SignKeyID != "cp-1" || string(got.Signature) != "sig" {
		t.Errorf("round trip lost data: %+v", got)
	}
	if got.SignedPayload != cp.SignedPayload {
		t.Error("SignedPayload did not round trip; verification depends on the exact stored bytes")
	}
}

// The structural backstop against two checkpointers racing on one stream.
func TestAppendCheckpointRejectsADuplicateToSeq(t *testing.T) {
	ctx := context.Background()
	s := New()
	streamID := id.NewStreamID()

	if err := s.AppendCheckpoint(ctx, newCP(streamID, 1, 100, "")); err != nil {
		t.Fatalf("first AppendCheckpoint: %v", err)
	}
	err := s.AppendCheckpoint(ctx, newCP(streamID, 1, 100, ""))
	if !errors.Is(err, checkpoint.ErrExists) {
		t.Fatalf("second AppendCheckpoint error = %v, want ErrCheckpointExists", err)
	}
}

// The constraint that catches two replicas reading different heads: they
// derive the same from_seq from the same stale latest checkpoint but claim
// different heads, so their to_seq values differ and only from_seq can tell
// them apart. Without this, both land and the two overlap permanently.
func TestAppendCheckpointRejectsADuplicateFromSeq(t *testing.T) {
	ctx := context.Background()
	s := New()
	streamID := id.NewStreamID()

	if err := s.AppendCheckpoint(ctx, newCP(streamID, 6, 10, "")); err != nil {
		t.Fatalf("first AppendCheckpoint: %v", err)
	}
	err := s.AppendCheckpoint(ctx, newCP(streamID, 6, 15, ""))
	if !errors.Is(err, checkpoint.ErrExists) {
		t.Fatalf("an overlapping checkpoint starting at the same from_seq returned %v, want ErrExists", err)
	}
}

// A different stream starting at the same sequence is not a duplicate.
func TestAppendCheckpointScopesTheFromSeqCheckToItsStream(t *testing.T) {
	ctx := context.Background()
	s := New()

	if err := s.AppendCheckpoint(ctx, newCP(id.NewStreamID(), 1, 10, "")); err != nil {
		t.Fatalf("first AppendCheckpoint: %v", err)
	}
	if err := s.AppendCheckpoint(ctx, newCP(id.NewStreamID(), 1, 10, "")); err != nil {
		t.Fatalf("another stream's first checkpoint was rejected: %v", err)
	}
}

func TestLatestCheckpointReturnsTheHighestToSeq(t *testing.T) {
	ctx := context.Background()
	s := New()
	streamID := id.NewStreamID()

	for _, r := range [][2]uint64{{1, 100}, {101, 200}, {201, 300}} {
		if err := s.AppendCheckpoint(ctx, newCP(streamID, r[0], r[1], "")); err != nil {
			t.Fatalf("AppendCheckpoint: %v", err)
		}
	}

	latest, err := s.LatestCheckpoint(ctx, streamID)
	if err != nil {
		t.Fatalf("LatestCheckpoint: %v", err)
	}
	if latest.ToSeq != 300 {
		t.Errorf("latest ToSeq = %d, want 300", latest.ToSeq)
	}
}

func TestLatestCheckpointOnAStreamWithNone(t *testing.T) {
	ctx := context.Background()
	if _, err := New().LatestCheckpoint(ctx, id.NewStreamID()); !errors.Is(err, checkpoint.ErrNotFound) {
		t.Errorf("LatestCheckpoint error = %v, want ErrCheckpointNotFound", err)
	}
}

// Verification asks for the checkpoints overlapping the range it is checking.
func TestCheckpointsInRangeOverlapsRatherThanContains(t *testing.T) {
	ctx := context.Background()
	s := New()
	streamID := id.NewStreamID()

	for _, r := range [][2]uint64{{1, 100}, {101, 200}, {201, 300}} {
		if err := s.AppendCheckpoint(ctx, newCP(streamID, r[0], r[1], "")); err != nil {
			t.Fatalf("AppendCheckpoint: %v", err)
		}
	}

	// A range sitting inside the middle checkpoint must still return it.
	got, err := s.CheckpointsInRange(ctx, streamID, 150, 160)
	if err != nil {
		t.Fatalf("CheckpointsInRange: %v", err)
	}
	if len(got) != 1 || got[0].ToSeq != 200 {
		t.Fatalf("got %d checkpoints, want the one covering 101-200", len(got))
	}

	// A range spanning two must return both, ascending.
	got, err = s.CheckpointsInRange(ctx, streamID, 50, 250)
	if err != nil {
		t.Fatalf("CheckpointsInRange: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d checkpoints, want 3 overlapping 50-250", len(got))
	}
	if got[0].ToSeq != 100 || got[2].ToSeq != 300 {
		t.Error("CheckpointsInRange must return ascending by ToSeq")
	}
}

func TestCheckpointsAreScopedToTheirStream(t *testing.T) {
	ctx := context.Background()
	s := New()
	a, b := id.NewStreamID(), id.NewStreamID()

	if err := s.AppendCheckpoint(ctx, newCP(a, 1, 100, "")); err != nil {
		t.Fatalf("AppendCheckpoint: %v", err)
	}
	got, err := s.CheckpointsInRange(ctx, b, 1, 1000)
	if err != nil {
		t.Fatalf("CheckpointsInRange: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("stream b saw %d of stream a's checkpoints", len(got))
	}
}
