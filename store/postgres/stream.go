package postgres

import (
	"context"
	"fmt"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/stream"
)

// CreateStream initializes a new hash chain stream.
func (s *Store) CreateStream(ctx context.Context, st *stream.Stream) error {
	m := fromStream(st)
	_, err := s.pg.NewInsert(m).Exec(ctx)
	return err
}

// GetStream returns a stream by ID.
func (s *Store) GetStream(ctx context.Context, streamID id.ID) (*stream.Stream, error) {
	m := new(StreamModel)
	err := s.pg.NewSelect(m).Where("id = $1", streamID.String()).Scan(ctx)
	if err != nil {
		return nil, groveError(err, chronicle.ErrStreamNotFound)
	}

	st, err := toStream(m)
	if err != nil {
		return nil, fmt.Errorf("failed to convert stream model: %w", err)
	}

	return st, nil
}

// GetStreamByScope returns the stream for a given app+tenant scope.
func (s *Store) GetStreamByScope(ctx context.Context, appID, tenantID string) (*stream.Stream, error) {
	m := new(StreamModel)
	err := s.pg.NewSelect(m).
		Where("app_id = $1", appID).
		Where("tenant_id = $2", tenantID).
		Scan(ctx)
	if err != nil {
		return nil, groveError(err, chronicle.ErrStreamNotFound)
	}

	st, err := toStream(m)
	if err != nil {
		return nil, fmt.Errorf("failed to convert stream model: %w", err)
	}

	return st, nil
}

// ListStreams returns all streams with pagination.
func (s *Store) ListStreams(ctx context.Context, opts stream.ListOpts) ([]*stream.Stream, error) {
	var models []StreamModel
	err := s.pg.NewSelect(&models).
		OrderExpr("s.created_at DESC").
		Limit(opts.Limit).
		Offset(opts.Offset).
		Scan(ctx)
	if err != nil {
		return nil, err
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
	result, err := s.pg.NewUpdate((*StreamModel)(nil)).
		Set("head_hash = $1", hash).
		Set("head_seq = $1", seq).
		Set("updated_at = NOW()").
		Where("id = $1", streamID.String()).
		Exec(ctx)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows == 0 {
		return fmt.Errorf("%w: stream %s", chronicle.ErrStreamNotFound, streamID)
	}

	return nil
}
