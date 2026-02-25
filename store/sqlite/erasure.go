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
	m := fromErasure(e)
	_, err := s.sdb.NewInsert(m).Exec(ctx)
	return err
}

// GetErasure returns an erasure record by ID.
func (s *Store) GetErasure(ctx context.Context, erasureID id.ID) (*erasure.Erasure, error) {
	m := new(ErasureModel)
	err := s.sdb.NewSelect(m).Where("id = ?", erasureID.String()).Scan(ctx)
	if err != nil {
		return nil, groveError(err, chronicle.ErrErasureNotFound)
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
	err := s.sdb.NewSelect(&models).
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
	count, err := s.sdb.NewSelect((*EventModel)(nil)).
		Where("subject_id = ?", subjectID).
		Count(ctx)
	return count, err
}

// MarkErased updates events to show [ERASED] for a given subject.
func (s *Store) MarkErased(ctx context.Context, subjectID string, erasureID id.ID) (int64, error) {
	result, err := s.sdb.NewUpdate((*EventModel)(nil)).
		Set("erased = 1").
		Set("erased_at = ?", now().Format("2006-01-02T15:04:05.999999999Z07:00")).
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
