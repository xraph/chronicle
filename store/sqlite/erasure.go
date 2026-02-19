package sqlite

import (
	"context"
	"fmt"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/id"
)

// RecordErasure persists an erasure event.
func (s *Store) RecordErasure(ctx context.Context, e *erasure.Erasure) error {
	query := `
		INSERT INTO chronicle_erasures (
			id, subject_id, reason, requested_by, events_affected,
			key_destroyed, app_id, tenant_id, created_at
		) VALUES (
			?, ?, ?, ?, ?, ?, ?, ?, ?
		)`

	_, err := s.db.ExecContext(ctx, query,
		e.ID.String(), e.SubjectID, e.Reason, e.RequestedBy, e.EventsAffected,
		boolToInt(e.KeyDestroyed), e.AppID, e.TenantID, formatTime(e.CreatedAt),
	)
	return err
}

// GetErasure returns an erasure record by ID.
func (s *Store) GetErasure(ctx context.Context, erasureID id.ID) (*erasure.Erasure, error) {
	query := `
		SELECT
			id, subject_id, reason, requested_by, events_affected,
			key_destroyed, app_id, tenant_id, created_at
		FROM chronicle_erasures
		WHERE id = ?`

	e := &erasure.Erasure{}
	var (
		idStr        string
		keyDestroyed int
		createdAt    string
	)

	err := s.db.QueryRowContext(ctx, query, erasureID.String()).Scan(
		&idStr, &e.SubjectID, &e.Reason, &e.RequestedBy, &e.EventsAffected,
		&keyDestroyed, &e.AppID, &e.TenantID, &createdAt,
	)
	if err != nil {
		return nil, sqliteError(err, chronicle.ErrErasureNotFound)
	}

	parsedID, err := id.ParseErasureID(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse erasure ID %q: %w", idStr, err)
	}
	e.ID = parsedID
	e.KeyDestroyed = keyDestroyed != 0

	e.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	return e, nil
}

// ListErasures returns erasure records with pagination.
func (s *Store) ListErasures(ctx context.Context, opts erasure.ListOpts) ([]*erasure.Erasure, error) {
	query := `
		SELECT
			id, subject_id, reason, requested_by, events_affected,
			key_destroyed, app_id, tenant_id, created_at
		FROM chronicle_erasures
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?`

	rows, err := s.db.QueryContext(ctx, query, opts.Limit, opts.Offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list erasures: %w", err)
	}
	defer rows.Close()

	var erasures []*erasure.Erasure
	for rows.Next() {
		e := &erasure.Erasure{}
		var (
			idStr        string
			keyDestroyed int
			createdAt    string
		)

		err := rows.Scan(
			&idStr, &e.SubjectID, &e.Reason, &e.RequestedBy, &e.EventsAffected,
			&keyDestroyed, &e.AppID, &e.TenantID, &createdAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan erasure row: %w", err)
		}

		parsedID, err := id.ParseErasureID(idStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse erasure ID %q: %w", idStr, err)
		}
		e.ID = parsedID
		e.KeyDestroyed = keyDestroyed != 0

		e.CreatedAt, err = parseTime(createdAt)
		if err != nil {
			return nil, fmt.Errorf("failed to parse created_at: %w", err)
		}

		erasures = append(erasures, e)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate erasure rows: %w", err)
	}

	return erasures, nil
}

// CountBySubject returns the number of events for a subject.
func (s *Store) CountBySubject(ctx context.Context, subjectID string) (int64, error) {
	query := `SELECT COUNT(*) FROM chronicle_events WHERE subject_id = ?`

	var count int64
	err := s.db.QueryRowContext(ctx, query, subjectID).Scan(&count)
	return count, err
}

// MarkErased updates events to show [ERASED] for a given subject.
func (s *Store) MarkErased(ctx context.Context, subjectID string, erasureID id.ID) (int64, error) {
	query := `
		UPDATE chronicle_events
		SET erased = 1, erased_at = datetime('now'), erasure_id = ?
		WHERE subject_id = ?`

	result, err := s.db.ExecContext(ctx, query, erasureID.String(), subjectID)
	if err != nil {
		return 0, fmt.Errorf("failed to mark events erased: %w", err)
	}

	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return n, nil
}

// boolToInt converts a boolean to an integer for SQLite storage.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
