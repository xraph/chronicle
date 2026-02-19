package stream

import (
	"context"

	"github.com/xraph/chronicle/id"
)

// Store manages hash chain streams.
type Store interface {
	// CreateStream initializes a new hash chain stream.
	CreateStream(ctx context.Context, s *Stream) error

	// GetStream returns a stream by ID.
	GetStream(ctx context.Context, streamID id.ID) (*Stream, error)

	// GetStreamByScope returns the stream for a given app+tenant scope.
	GetStreamByScope(ctx context.Context, appID, tenantID string) (*Stream, error)

	// ListStreams returns all streams.
	ListStreams(ctx context.Context, opts ListOpts) ([]*Stream, error)

	// UpdateStreamHead updates the stream's head hash and sequence after append.
	UpdateStreamHead(ctx context.Context, streamID id.ID, hash string, seq uint64) error
}
