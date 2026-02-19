package sqlite

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
			?, ?, ?, ?, ?, ?, ?
		)`

	_, err := s.db.ExecContext(ctx, query,
		st.ID.String(), st.AppID, st.TenantID, st.HeadHash, st.HeadSeq,
		formatTime(st.CreatedAt), formatTime(st.UpdatedAt),
	)
	return err
}

// GetStream returns a stream by ID.
func (s *Store) GetStream(ctx context.Context, streamID id.ID) (*stream.Stream, error) {
	query := `
		SELECT id, app_id, tenant_id, head_hash, head_seq, created_at, updated_at
		FROM chronicle_streams
		WHERE id = ?`

	return s.scanStream(ctx, query, streamID.String())
}

// GetStreamByScope returns the stream for a given app+tenant scope.
func (s *Store) GetStreamByScope(ctx context.Context, appID, tenantID string) (*stream.Stream, error) {
	query := `
		SELECT id, app_id, tenant_id, head_hash, head_seq, created_at, updated_at
		FROM chronicle_streams
		WHERE app_id = ? AND tenant_id = ?`

	return s.scanStream(ctx, query, appID, tenantID)
}

// ListStreams returns all streams with pagination.
func (s *Store) ListStreams(ctx context.Context, opts stream.ListOpts) ([]*stream.Stream, error) {
	query := `
		SELECT id, app_id, tenant_id, head_hash, head_seq, created_at, updated_at
		FROM chronicle_streams
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?`

	rows, err := s.db.QueryContext(ctx, query, opts.Limit, opts.Offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list streams: %w", err)
	}
	defer rows.Close()

	var streams []*stream.Stream
	for rows.Next() {
		st, err := s.scanStreamRow(rows)
		if err != nil {
			return nil, err
		}
		streams = append(streams, st)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate stream rows: %w", err)
	}

	return streams, nil
}

// UpdateStreamHead updates the stream's head hash and sequence after append.
func (s *Store) UpdateStreamHead(ctx context.Context, streamID id.ID, hash string, seq uint64) error {
	query := `
		UPDATE chronicle_streams
		SET head_hash = ?, head_seq = ?, updated_at = datetime('now')
		WHERE id = ?`

	result, err := s.db.ExecContext(ctx, query, hash, seq, streamID.String())
	if err != nil {
		return fmt.Errorf("failed to update stream head: %w", err)
	}

	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if n == 0 {
		return fmt.Errorf("%w: stream %s", chronicle.ErrStreamNotFound, streamID)
	}

	return nil
}

// scanStream queries a single stream row and scans it.
func (s *Store) scanStream(ctx context.Context, query string, args ...interface{}) (*stream.Stream, error) {
	st := &stream.Stream{}
	var (
		idStr     string
		createdAt string
		updatedAt string
	)

	err := s.db.QueryRowContext(ctx, query, args...).Scan(
		&idStr, &st.AppID, &st.TenantID, &st.HeadHash, &st.HeadSeq,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return nil, sqliteError(err, chronicle.ErrStreamNotFound)
	}

	parsedID, err := id.ParseStreamID(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse stream ID %q: %w", idStr, err)
	}
	st.ID = parsedID

	st.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	st.UpdatedAt, err = parseTime(updatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse updated_at: %w", err)
	}

	return st, nil
}

// scanStreamRow is a row scanner interface for sql.Rows.
type rowScanner interface {
	Scan(dest ...interface{}) error
}

// scanStreamRow scans a stream from sql.Rows.
func (s *Store) scanStreamRow(row rowScanner) (*stream.Stream, error) {
	st := &stream.Stream{}
	var (
		idStr     string
		createdAt string
		updatedAt string
	)

	err := row.Scan(
		&idStr, &st.AppID, &st.TenantID, &st.HeadHash, &st.HeadSeq,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan stream row: %w", err)
	}

	parsedID, err := id.ParseStreamID(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse stream ID %q: %w", idStr, err)
	}
	st.ID = parsedID

	st.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	st.UpdatedAt, err = parseTime(updatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse updated_at: %w", err)
	}

	return st, nil
}
