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

// CompleteErasure writes an erasure's outcome and marks it completed.
func (s *Store) CompleteErasure(ctx context.Context, erasureID id.ID, o erasure.Outcome) error {
	result, err := s.sdb.NewUpdate((*ErasureModel)(nil)).
		Set("status = ?", string(erasure.StatusCompleted)).
		Set("events_affected = ?", o.EventsAffected).
		Set("key_destroyed = ?", boolInt(o.KeyDestroyed)).
		Set("legacy_key_retained = ?", boolInt(o.LegacyKeyRetained)).
		Where("id = ?", erasureID.String()).
		Exec(ctx)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return chronicle.ErrErasureNotFound
	}
	return nil
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

// ListErasures returns erasure records matching opts, scoped before pagination.
func (s *Store) ListErasures(ctx context.Context, opts erasure.ListOpts) ([]*erasure.Erasure, error) {
	var models []ErasureModel
	q := s.sdb.NewSelect(&models)

	if opts.AppID != "" {
		q = q.Where("er.app_id = ?", opts.AppID)
	}
	if opts.TenantID != "" {
		q = q.Where("er.tenant_id = ?", opts.TenantID)
	}

	q = q.OrderExpr("er.created_at DESC")
	if opts.Limit > 0 {
		q = q.Limit(opts.Limit)
	}
	if opts.Offset > 0 {
		q = q.Offset(opts.Offset)
	}

	if err := q.Scan(ctx); err != nil {
		return nil, err
	}

	erasures := make([]*erasure.Erasure, 0, len(models))
	for i := range models {
		e, convErr := toErasure(&models[i])
		if convErr != nil {
			return nil, convErr
		}
		erasures = append(erasures, e)
	}

	return erasures, nil
}

// CountErasures returns the number of erasure records in the given scope.
func (s *Store) CountErasures(ctx context.Context, sc erasure.Scope) (int64, error) {
	q := s.sdb.NewSelect((*ErasureModel)(nil))
	if sc.AppID != "" {
		q = q.Where("er.app_id = ?", sc.AppID)
	}
	if sc.TenantID != "" {
		q = q.Where("er.tenant_id = ?", sc.TenantID)
	}
	return q.Count(ctx)
}

// CountBySubject returns the number of events for a subject within the query's
// scope.
//
// Security-critical: without the scope filter this reveals how many events other
// tenants hold on the subject.
func (s *Store) CountBySubject(ctx context.Context, sq erasure.SubjectQuery) (int64, error) {
	q := s.sdb.NewSelect((*EventModel)(nil)).Where("subject_id = ?", sq.SubjectID)
	if sq.AppID != "" {
		q = q.Where("app_id = ?", sq.AppID)
	}
	if sq.TenantID != "" {
		q = q.Where("tenant_id = ?", sq.TenantID)
	}
	return q.Count(ctx)
}

// MarkErased flags a subject's events as erased within the query's scope.
//
// Security-critical: without the scope filter any caller could flag every
// tenant's events for a guessed subject ID.
func (s *Store) MarkErased(
	ctx context.Context, sq erasure.SubjectQuery, erasureID id.ID,
) (int64, error) {
	q := s.sdb.NewUpdate((*EventModel)(nil)).
		Set("erased = 1").
		Set("erased_at = ?", formatTime(now())).
		Set("erasure_id = ?", erasureID.String()).
		Where("subject_id = ?", sq.SubjectID)

	if sq.AppID != "" {
		q = q.Where("app_id = ?", sq.AppID)
	}
	if sq.TenantID != "" {
		q = q.Where("tenant_id = ?", sq.TenantID)
	}

	result, err := q.Exec(ctx)
	if err != nil {
		return 0, err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}

	return rows, nil
}

// SubjectKeyUsage groups a subject's events across every scope by app, tenant,
// encryption key ID and erased flag.
//
// Security-critical in the other direction: it is unscoped on purpose, so the
// erasure service can see every scope sharing a legacy key. It must never back
// a response to a caller; see erasure.Store.
func (s *Store) SubjectKeyUsage(ctx context.Context, subjectID string) ([]erasure.KeyUsage, error) {
	rows, err := s.sdb.Query(ctx,
		`SELECT app_id, tenant_id, encryption_key_id, erased, COUNT(*)
		   FROM chronicle_events
		  WHERE subject_id = ?
		  GROUP BY app_id, tenant_id, encryption_key_id, erased`,
		subjectID,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var usage []erasure.KeyUsage
	for rows.Next() {
		var u erasure.KeyUsage
		var erased int64
		if err := rows.Scan(&u.AppID, &u.TenantID, &u.EncryptionKeyID, &erased, &u.Events); err != nil {
			return nil, err
		}
		u.Erased = erased != 0
		usage = append(usage, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return usage, nil
}
