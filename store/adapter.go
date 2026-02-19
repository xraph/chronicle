package store

import (
	"context"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/stream"
)

// Adapter wraps a composite Store to implement chronicle.Storer,
// bridging the gap between stream.Stream and chronicle.StreamInfo
// to avoid import cycles.
type Adapter struct {
	Store
}

// NewAdapter wraps a Store as a chronicle.Storer.
func NewAdapter(s Store) *Adapter {
	return &Adapter{Store: s}
}

// GetStreamByScope returns stream info for a given app+tenant scope.
func (a *Adapter) GetStreamByScope(ctx context.Context, appID, tenantID string) (*chronicle.StreamInfo, error) {
	s, err := a.Store.GetStreamByScope(ctx, appID, tenantID)
	if err != nil {
		return nil, err
	}
	return &chronicle.StreamInfo{
		ID:       s.ID,
		AppID:    s.AppID,
		TenantID: s.TenantID,
		HeadHash: s.HeadHash,
		HeadSeq:  s.HeadSeq,
	}, nil
}

// CreateStreamInfo creates a new stream from StreamInfo.
func (a *Adapter) CreateStreamInfo(ctx context.Context, info *chronicle.StreamInfo) error {
	s := &stream.Stream{
		Entity:   chronicle.NewEntity(),
		ID:       info.ID,
		AppID:    info.AppID,
		TenantID: info.TenantID,
		HeadHash: info.HeadHash,
		HeadSeq:  info.HeadSeq,
	}
	return a.CreateStream(ctx, s)
}

// UpdateStreamHead delegates to the underlying store.
func (a *Adapter) UpdateStreamHead(ctx context.Context, streamID id.ID, hash string, seq uint64) error {
	return a.Store.UpdateStreamHead(ctx, streamID, hash, seq)
}
