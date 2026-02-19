package verify

import (
	"context"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
)

// Store provides data access for hash chain verification.
type Store interface {
	// EventRange returns events in a sequence range for chain verification.
	EventRange(ctx context.Context, streamID id.ID, fromSeq, toSeq uint64) ([]*audit.Event, error)

	// Gaps detects missing sequence numbers in a range.
	Gaps(ctx context.Context, streamID id.ID, fromSeq, toSeq uint64) ([]uint64, error)
}
