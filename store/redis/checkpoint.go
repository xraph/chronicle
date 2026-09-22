package redis

import (
	"context"

	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/id"
)

// TODO(checkpoints): Task 3 gives postgres, sqlite, and mongo real checkpoint
// implementations. Redis stays on this stub permanently: a checkpoint is
// meant to be a durable root of trust, and Redis's persistence model is not a
// backend this project treats as durable enough for that job. Every method
// reports ErrUnsupported rather than silently discarding a checkpoint.

// AppendCheckpoint is not supported by this backend.
func (s *Store) AppendCheckpoint(_ context.Context, _ *checkpoint.Checkpoint) error {
	return checkpoint.ErrUnsupported
}

// LatestCheckpoint is not supported by this backend.
func (s *Store) LatestCheckpoint(_ context.Context, _ id.ID) (*checkpoint.Checkpoint, error) {
	return nil, checkpoint.ErrUnsupported
}

// CheckpointsInRange is not supported by this backend.
func (s *Store) CheckpointsInRange(
	_ context.Context, _ id.ID, _, _ uint64,
) ([]*checkpoint.Checkpoint, error) {
	return nil, checkpoint.ErrUnsupported
}

// GetCheckpoint is not supported by this backend.
func (s *Store) GetCheckpoint(_ context.Context, _ id.ID) (*checkpoint.Checkpoint, error) {
	return nil, checkpoint.ErrUnsupported
}

// ListCheckpoints is not supported by this backend.
func (s *Store) ListCheckpoints(
	_ context.Context, _ id.ID, _ checkpoint.ListOpts,
) ([]*checkpoint.Checkpoint, error) {
	return nil, checkpoint.ErrUnsupported
}
