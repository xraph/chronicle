package checkpoint

import (
	"context"
	"errors"

	"github.com/xraph/chronicle/id"
)

// Sentinel errors.
//
// These live here rather than in the root package's errors.go, next to
// ErrEventNotFound and its neighbors, because checkpoint must not import
// chronicle: chronicle imports verify, stream imports chronicle, and a later
// task has verify import checkpoint. An import back to chronicle from here
// would close that into a cycle.
var (
	// ErrNotFound is returned when a checkpoint cannot be found.
	ErrNotFound = errors.New("checkpoint: not found")

	// ErrExists is returned when a checkpoint already covers a stream's
	// sequence: another one already ends at the same to_seq, or another one
	// already starts at the same from_seq.
	//
	// Two checkpointers racing on one stream is expected: a background ticker
	// and an operator-triggered run can overlap, as can two replicas' tickers.
	// Rather than rely on lock discipline, which only ever covers one
	// process, the store makes an overlapping checkpoint structurally
	// impossible and the loser of the race gets this. It is an ordinary
	// outcome, not a fault: the scheduler treats it as one.
	ErrExists = errors.New("checkpoint: already exists for this sequence")

	// ErrUnsupported is returned by backends that cannot store checkpoints
	// durably enough to be a root of trust.
	ErrUnsupported = errors.New("checkpoint: this store does not support checkpoints")
)

// Store persists signed checkpoints.
//
// Checkpoints are append-only. There is no update and no delete: a checkpoint
// that could be revised would assert nothing.
type Store interface {
	// AppendCheckpoint persists a checkpoint. It returns ErrExists if one
	// already covers the same (stream, to_seq).
	AppendCheckpoint(ctx context.Context, cp *Checkpoint) error

	// LatestCheckpoint returns the checkpoint with the highest ToSeq for a
	// stream, or ErrNotFound when the stream has none.
	LatestCheckpoint(ctx context.Context, streamID id.ID) (*Checkpoint, error)

	// CheckpointsInRange returns every checkpoint whose range OVERLAPS
	// [fromSeq, toSeq], ascending by ToSeq.
	//
	// Overlap rather than containment, because a caller verifying sequences
	// 150 to 160 still needs the checkpoint covering 101 to 200: that is the
	// one whose assertion those events fall under.
	CheckpointsInRange(ctx context.Context, streamID id.ID, fromSeq, toSeq uint64) ([]*Checkpoint, error)

	// GetCheckpoint returns one checkpoint by ID.
	GetCheckpoint(ctx context.Context, checkpointID id.ID) (*Checkpoint, error)

	// ListCheckpoints returns a stream's checkpoints, newest first.
	ListCheckpoints(ctx context.Context, streamID id.ID, opts ListOpts) ([]*Checkpoint, error)
}
