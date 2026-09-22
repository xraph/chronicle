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

	// UpdateStreamScheme moves the stream's digest pin to scheme, applying from
	// sequence since.
	//
	// It exists so turning a stronger digest on actually takes effect on streams
	// that already exist. Without it the pin written at creation is the only pin
	// the stream ever has, and a chain that is now being written under a keyed
	// scheme keeps advertising the weaker one, which is exactly the claim a
	// downgrade check needs to be true. Callers must only ever move the pin
	// upward; see chronicle.Chronicle's resolveStream.
	UpdateStreamScheme(ctx context.Context, streamID id.ID, scheme string, since uint64) error
}
