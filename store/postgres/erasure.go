package postgres

import (
	"context"

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
			$1, $2, $3, $4, $5, $6, $7, $8, $9
		)`

	_, err := s.pool.Exec(ctx, query,
		e.ID, e.SubjectID, e.Reason, e.RequestedBy, e.EventsAffected,
		e.KeyDestroyed, e.AppID, e.TenantID, e.CreatedAt,
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
		WHERE id = $1`

	e := &erasure.Erasure{}
	err := s.pool.QueryRow(ctx, query, erasureID).Scan(
		&e.ID, &e.SubjectID, &e.Reason, &e.RequestedBy, &e.EventsAffected,
		&e.KeyDestroyed, &e.AppID, &e.TenantID, &e.CreatedAt,
	)

	if err != nil {
		return nil, pgxError(err, chronicle.ErrErasureNotFound)
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
		LIMIT $1 OFFSET $2`

	rows, err := s.pool.Query(ctx, query, opts.Limit, opts.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var erasures []*erasure.Erasure
	for rows.Next() {
		e := &erasure.Erasure{}
		err := rows.Scan(
			&e.ID, &e.SubjectID, &e.Reason, &e.RequestedBy, &e.EventsAffected,
			&e.KeyDestroyed, &e.AppID, &e.TenantID, &e.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		erasures = append(erasures, e)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return erasures, nil
}

// CountBySubject returns the number of events for a subject.
func (s *Store) CountBySubject(ctx context.Context, subjectID string) (int64, error) {
	query := `SELECT COUNT(*) FROM chronicle_events WHERE subject_id = $1`

	var count int64
	err := s.pool.QueryRow(ctx, query, subjectID).Scan(&count)
	return count, err
}

// MarkErased updates events to show [ERASED] for a given subject.
func (s *Store) MarkErased(ctx context.Context, subjectID string, erasureID id.ID) (int64, error) {
	query := `
		UPDATE chronicle_events
		SET erased = true, erased_at = NOW(), erasure_id = $2
		WHERE subject_id = $1`

	result, err := s.pool.Exec(ctx, query, subjectID, erasureID)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected(), nil
}
