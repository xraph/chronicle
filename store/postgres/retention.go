package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
)

// SavePolicy persists a retention policy (INSERT or UPDATE on conflict).
func (s *Store) SavePolicy(ctx context.Context, p *retention.Policy) error {
	m := fromPolicy(p)
	_, err := s.pg.NewInsert(m).
		OnConflict("(category) DO UPDATE").
		Set("duration = EXCLUDED.duration").
		Set("archive = EXCLUDED.archive").
		Set("app_id = EXCLUDED.app_id").
		Set("updated_at = EXCLUDED.updated_at").
		Exec(ctx)
	return err
}

// GetPolicy returns a retention policy by ID.
func (s *Store) GetPolicy(ctx context.Context, policyID id.ID) (*retention.Policy, error) {
	m := new(RetentionPolicyModel)
	err := s.pg.NewSelect(m).Where("id = $1", policyID.String()).Scan(ctx)
	if err != nil {
		return nil, groveError(err, chronicle.ErrPolicyNotFound)
	}

	p, err := toPolicy(m)
	if err != nil {
		return nil, fmt.Errorf("failed to convert policy model: %w", err)
	}

	return p, nil
}

// ListPolicies returns all retention policies.
func (s *Store) ListPolicies(ctx context.Context) ([]*retention.Policy, error) {
	var models []RetentionPolicyModel
	err := s.pg.NewSelect(&models).
		OrderExpr("rp.created_at DESC").
		Scan(ctx)
	if err != nil {
		return nil, err
	}

	policies := make([]*retention.Policy, 0, len(models))
	for i := range models {
		p, err := toPolicy(&models[i])
		if err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}

	return policies, nil
}

// DeletePolicy removes a retention policy.
func (s *Store) DeletePolicy(ctx context.Context, policyID id.ID) error {
	result, err := s.pg.NewDelete((*RetentionPolicyModel)(nil)).
		Where("id = $1", policyID.String()).
		Exec(ctx)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows == 0 {
		return fmt.Errorf("%w: policy %s", chronicle.ErrPolicyNotFound, policyID)
	}

	return nil
}

// EventsOlderThan returns events older than a given time for a category.
func (s *Store) EventsOlderThan(ctx context.Context, category string, before time.Time) ([]*audit.Event, error) {
	var models []EventModel
	err := s.pg.NewSelect(&models).
		Where("e.category = $1", category).
		Where("e.timestamp < $2", before).
		OrderExpr("e.timestamp ASC").
		Scan(ctx)
	if err != nil {
		return nil, err
	}

	return toEventSlice(models)
}

// PurgeEvents permanently deletes events by IDs.
func (s *Store) PurgeEvents(ctx context.Context, eventIDs []id.ID) (int64, error) {
	if len(eventIDs) == 0 {
		return 0, nil
	}

	// Convert TypeIDs to strings for the query.
	ids := make([]string, 0, len(eventIDs))
	for _, eid := range eventIDs {
		ids = append(ids, eid.String())
	}

	result, err := s.pg.Exec(ctx,
		"DELETE FROM chronicle_events WHERE id = ANY($1)", ids)
	if err != nil {
		return 0, err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}

	return rows, nil
}

// RecordArchive records that a batch of events was archived.
func (s *Store) RecordArchive(ctx context.Context, a *retention.Archive) error {
	m := fromArchive(a)
	_, err := s.pg.NewInsert(m).Exec(ctx)
	return err
}

// ListArchives returns archive records with pagination.
func (s *Store) ListArchives(ctx context.Context, opts retention.ListOpts) ([]*retention.Archive, error) {
	var models []ArchiveModel
	err := s.pg.NewSelect(&models).
		OrderExpr("a.created_at DESC").
		Limit(opts.Limit).
		Offset(opts.Offset).
		Scan(ctx)
	if err != nil {
		return nil, err
	}

	archives := make([]*retention.Archive, 0, len(models))
	for i := range models {
		a, err := toArchive(&models[i])
		if err != nil {
			return nil, err
		}
		archives = append(archives, a)
	}

	return archives, nil
}
