package mongo

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/stream"
)

// CreateStream initializes a new hash chain stream.
func (s *Store) CreateStream(ctx context.Context, st *stream.Stream) error {
	m := fromStream(st)
	_, err := s.mdb.NewInsert(m).Exec(ctx)
	return err
}

// GetStream returns a stream by ID.
func (s *Store) GetStream(ctx context.Context, streamID id.ID) (*stream.Stream, error) {
	var m StreamModel
	err := s.mdb.NewFind(&m).Filter(bson.M{"_id": streamID.String()}).Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, chronicle.ErrStreamNotFound
		}
		return nil, fmt.Errorf("failed to get stream: %w", err)
	}

	st, err := toStream(&m)
	if err != nil {
		return nil, fmt.Errorf("failed to convert stream model: %w", err)
	}

	return st, nil
}

// GetStreamByScope returns the stream for a given app+tenant scope.
func (s *Store) GetStreamByScope(ctx context.Context, appID, tenantID string) (*stream.Stream, error) {
	var m StreamModel
	err := s.mdb.NewFind(&m).
		Filter(bson.M{"app_id": appID, "tenant_id": tenantID}).
		Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, chronicle.ErrStreamNotFound
		}
		return nil, fmt.Errorf("failed to get stream by scope: %w", err)
	}

	st, err := toStream(&m)
	if err != nil {
		return nil, fmt.Errorf("failed to convert stream model: %w", err)
	}

	return st, nil
}

// ListStreams returns all streams with pagination.
func (s *Store) ListStreams(ctx context.Context, opts stream.ListOpts) ([]*stream.Stream, error) {
	var models []StreamModel
	findQ := s.mdb.NewFind(&models).
		Filter(bson.M{}).
		Sort(bson.D{{Key: "created_at", Value: -1}})

	if opts.Limit > 0 {
		findQ = findQ.Limit(int64(opts.Limit))
	}
	if opts.Offset > 0 {
		findQ = findQ.Skip(int64(opts.Offset))
	}

	if err := findQ.Scan(ctx); err != nil {
		return nil, fmt.Errorf("failed to list streams: %w", err)
	}

	streams := make([]*stream.Stream, 0, len(models))
	for i := range models {
		st, err := toStream(&models[i])
		if err != nil {
			return nil, err
		}
		streams = append(streams, st)
	}

	return streams, nil
}

// UpdateStreamHead updates the stream's head hash and sequence after append.
func (s *Store) UpdateStreamHead(ctx context.Context, streamID id.ID, hash string, seq uint64) error {
	res, err := s.mdb.NewUpdate((*StreamModel)(nil)).
		Filter(bson.M{"_id": streamID.String()}).
		Set("head_hash", hash).
		Set("head_seq", seq).
		Set("updated_at", time.Now().UTC()).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to update stream head: %w", err)
	}

	if res.MatchedCount() == 0 {
		return fmt.Errorf("%w: stream %s", chronicle.ErrStreamNotFound, streamID)
	}

	return nil
}
