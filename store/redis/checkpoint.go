package redis

import (
	"context"

	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/id"
)

// Checkpoints are deliberately unsupported on Redis.
//
// The README positions this backend as a read-through cache layer, and a
// cache is the wrong home for a root of trust: a checkpoint that can be
// evicted asserts nothing. The extension refuses to start when checkpoints
// are enabled on a backend that returns this, rather than running silently
// without them.

// AppendCheckpoint is not supported by this backend.
func (s *Store) AppendCheckpoint(context.Context, *checkpoint.Checkpoint) error {
	return checkpoint.ErrUnsupported
}

// LatestCheckpoint is not supported by this backend.
func (s *Store) LatestCheckpoint(context.Context, id.ID) (*checkpoint.Checkpoint, error) {
	return nil, checkpoint.ErrUnsupported
}

// CheckpointsInRange is not supported by this backend.
func (s *Store) CheckpointsInRange(
	context.Context, id.ID, uint64, uint64,
) ([]*checkpoint.Checkpoint, error) {
	return nil, checkpoint.ErrUnsupported
}

// GetCheckpoint is not supported by this backend.
func (s *Store) GetCheckpoint(context.Context, id.ID) (*checkpoint.Checkpoint, error) {
	return nil, checkpoint.ErrUnsupported
}

// ListCheckpoints is not supported by this backend.
func (s *Store) ListCheckpoints(
	context.Context, id.ID, checkpoint.ListOpts,
) ([]*checkpoint.Checkpoint, error) {
	return nil, checkpoint.ErrUnsupported
}
