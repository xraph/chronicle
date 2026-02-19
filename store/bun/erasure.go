package bunstore

import (
	"context"
	"fmt"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/id"
)

// RecordErasure persists an erasure event.
func (s *Store) RecordErasure(ctx context.Context, e *erasure.Erasure) error {
	m := fromErasure(e)
	_, err := s.db.NewInsert().Model(m).Exec(ctx)
	return err
}

// GetErasure returns an erasure record by ID.
func (s *Store) GetErasure(ctx context.Context, erasureID id.ID) (*erasure.Erasure, error) {
	m := new(ErasureModel)
	err := s.db.NewSelect().Model(m).Where("id = ?", erasureID.String()).Scan(ctx)
	if err != nil {
		return nil, bunError(err, chronicle.ErrErasureNotFound)
	}

	e, err := toErasure(m)
	if err != nil {
		return nil, fmt.Errorf("failed to convert erasure model: %w", err)
	}

	return e, nil
}

// ListErasures returns erasure records with pagination.
func (s *Store) ListErasures(ctx context.Context, opts erasure.ListOpts) ([]*erasure.Erasure, error) {
	var models []ErasureModel
	err := s.db.NewSelect().Model(&models).
		OrderExpr("er.created_at DESC").
		Limit(opts.Limit).
		Offset(opts.Offset).
		Scan(ctx)
	if err != nil {
		return nil, err
	}

	erasures := make([]*erasure.Erasure, 0, len(models))
	for i := range models {
		e, err := toErasure(&models[i])
		if err != nil {
			return nil, err
		}
		erasures = append(erasures, e)
	}

	return erasures, nil
}

// CountBySubject returns the number of events for a subject.
func (s *Store) CountBySubject(ctx context.Context, subjectID string) (int64, error) {
	var count int64
	err := s.db.NewSelect().
		TableExpr("chronicle_events").
		ColumnExpr("COUNT(*)").
		Where("subject_id = ?", subjectID).
		Scan(ctx, &count)
	return count, err
}

// MarkErased updates events to show [ERASED] for a given subject.
func (s *Store) MarkErased(ctx context.Context, subjectID string, erasureID id.ID) (int64, error) {
	result, err := s.db.NewUpdate().
		TableExpr("chronicle_events").
		Set("erased = true").
		Set("erased_at = NOW()").
		Set("erasure_id = ?", erasureID.String()).
		Where("subject_id = ?", subjectID).
		Exec(ctx)
	if err != nil {
		return 0, err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}

	return rows, nil
}
