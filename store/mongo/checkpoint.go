package mongo

import (
	"context"

	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/id"
)

// TODO(checkpoints): Task 3 replaces this stub with a real implementation.
//
// This backend does not yet store checkpoints. Embedding checkpoint.Store in
// the composite store.Store means every backend must satisfy it to keep the
// module building, so until the real implementation lands, every method
// reports ErrUnsupported rather than silently discarding a checkpoint.

// AppendCheckpoint is not yet implemented for this backend.
func (s *Store) AppendCheckpoint(_ context.Context, _ *checkpoint.Checkpoint) error {
	return checkpoint.ErrUnsupported
}

// LatestCheckpoint is not yet implemented for this backend.
func (s *Store) LatestCheckpoint(_ context.Context, _ id.ID) (*checkpoint.Checkpoint, error) {
	return nil, checkpoint.ErrUnsupported
}

// CheckpointsInRange is not yet implemented for this backend.
func (s *Store) CheckpointsInRange(
	_ context.Context, _ id.ID, _, _ uint64,
) ([]*checkpoint.Checkpoint, error) {
	return nil, checkpoint.ErrUnsupported
}

// GetCheckpoint is not yet implemented for this backend.
func (s *Store) GetCheckpoint(_ context.Context, _ id.ID) (*checkpoint.Checkpoint, error) {
	return nil, checkpoint.ErrUnsupported
}

// ListCheckpoints is not yet implemented for this backend.
func (s *Store) ListCheckpoints(
	_ context.Context, _ id.ID, _ checkpoint.ListOpts,
) ([]*checkpoint.Checkpoint, error) {
	return nil, checkpoint.ErrUnsupported
}
