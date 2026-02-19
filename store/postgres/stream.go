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
	query := `
		INSERT INTO chronicle_streams (
			id, app_id, tenant_id, head_hash, head_seq, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7
		)`

	_, err := s.pool.Exec(ctx, query,
		st.ID, st.AppID, st.TenantID, st.HeadHash, st.HeadSeq,
		st.CreatedAt, st.UpdatedAt,
	)
	return err
}

// GetStream returns a stream by ID.
func (s *Store) GetStream(ctx context.Context, streamID id.ID) (*stream.Stream, error) {
	query := `
		SELECT id, app_id, tenant_id, head_hash, head_seq, created_at, updated_at
		FROM chronicle_streams
		WHERE id = $1`

	st := &stream.Stream{}
	err := s.pool.QueryRow(ctx, query, streamID).Scan(
		&st.ID, &st.AppID, &st.TenantID, &st.HeadHash, &st.HeadSeq,
		&st.CreatedAt, &st.UpdatedAt,
	)

	if err != nil {
		return nil, pgxError(err, chronicle.ErrStreamNotFound)
	}

	return st, nil
}

// GetStreamByScope returns the stream for a given app+tenant scope.
func (s *Store) GetStreamByScope(ctx context.Context, appID, tenantID string) (*stream.Stream, error) {
	query := `
		SELECT id, app_id, tenant_id, head_hash, head_seq, created_at, updated_at
		FROM chronicle_streams
		WHERE app_id = $1 AND tenant_id = $2`

	st := &stream.Stream{}
	err := s.pool.QueryRow(ctx, query, appID, tenantID).Scan(
		&st.ID, &st.AppID, &st.TenantID, &st.HeadHash, &st.HeadSeq,
		&st.CreatedAt, &st.UpdatedAt,
	)

	if err != nil {
		return nil, pgxError(err, chronicle.ErrStreamNotFound)
	}

	return st, nil
}

// ListStreams returns all streams with pagination.
func (s *Store) ListStreams(ctx context.Context, opts stream.ListOpts) ([]*stream.Stream, error) {
	query := `
		SELECT id, app_id, tenant_id, head_hash, head_seq, created_at, updated_at
		FROM chronicle_streams
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2`

	rows, err := s.pool.Query(ctx, query, opts.Limit, opts.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var streams []*stream.Stream
	for rows.Next() {
		st := &stream.Stream{}
		err := rows.Scan(
			&st.ID, &st.AppID, &st.TenantID, &st.HeadHash, &st.HeadSeq,
			&st.CreatedAt, &st.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		streams = append(streams, st)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return streams, nil
}

// UpdateStreamHead updates the stream's head hash and sequence after append.
func (s *Store) UpdateStreamHead(ctx context.Context, streamID id.ID, hash string, seq uint64) error {
	query := `
		UPDATE chronicle_streams
		SET head_hash = $2, head_seq = $3, updated_at = NOW()
		WHERE id = $1`

	result, err := s.pool.Exec(ctx, query, streamID, hash, seq)
	if err != nil {
		return err
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("%w: stream %s", chronicle.ErrStreamNotFound, streamID)
	}

	return nil
}
