package postgres

import (
	"context"
	"fmt"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
)

// SavePolicy persists a retention policy (INSERT or UPDATE on conflict).
//
// The conflict target is the owning scope plus the category, not the category
// alone: a policy must never overwrite, or take ownership of, another app or
// tenant's policy for the same category.
func (s *Store) SavePolicy(ctx context.Context, p *retention.Policy) error {
	m := fromPolicy(p)
	_, err := s.pg.NewInsert(m).
		OnConflict("(app_id, tenant_id, category) DO UPDATE").
		Set("duration = EXCLUDED.duration").
		Set("archive = EXCLUDED.archive").
		Set("updated_at = EXCLUDED.updated_at").
		Exec(ctx)
	return err
}

// GetPolicy returns a retention policy by ID.
func (s *Store) GetPolicy(ctx context.Context, policyID id.ID) (*retention.Policy, error) {
	m := new(RetentionPolicyModel)
	err := s.pg.NewSelect(m).Where("id = ?", policyID.String()).Scan(ctx)
	if err != nil {
		return nil, groveError(err, chronicle.ErrPolicyNotFound)
	}

	p, err := toPolicy(m)
	if err != nil {
		return nil, fmt.Errorf("failed to convert policy model: %w", err)
	}

	return p, nil
}

// ListPolicies returns retention policies matching opts, scoped before
// pagination so a caller's own rows are never hidden behind another tenant's.
func (s *Store) ListPolicies(
	ctx context.Context, opts retention.ListPoliciesOpts,
) ([]*retention.Policy, error) {
	var models []RetentionPolicyModel
	q := s.pg.NewSelect(&models)

	if opts.AppID != "" {
		q.Where("rp.app_id = ?", opts.AppID)
	}
	if opts.TenantID != "" {
		q.Where("rp.tenant_id = ?", opts.TenantID)
	}

	q = q.OrderExpr("rp.created_at DESC")
	if opts.Limit > 0 {
		q = q.Limit(opts.Limit)
	}
	if opts.Offset > 0 {
		q = q.Offset(opts.Offset)
	}

	if err := q.Scan(ctx); err != nil {
		return nil, err
	}

	policies := make([]*retention.Policy, 0, len(models))
	for i := range models {
		p, convErr := toPolicy(&models[i])
		if convErr != nil {
			return nil, convErr
		}
		policies = append(policies, p)
	}

	return policies, nil
}

// DeletePolicy removes a retention policy.
func (s *Store) DeletePolicy(ctx context.Context, policyID id.ID) error {
	result, err := s.pg.NewDelete((*RetentionPolicyModel)(nil)).
		Where("id = ?", policyID.String()).
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

// EventsOlderThan returns the events the purge query selects.
//
// Security-critical: the scope filter is what keeps one tenant's policy from
// selecting, and therefore purging, every tenant's history. The bound keeps a
// large backlog from being loaded into memory all at once.
func (s *Store) EventsOlderThan(
	ctx context.Context, pq retention.PurgeQuery,
) ([]*audit.Event, error) {
	var models []EventModel
	q := s.pg.NewSelect(&models).Where("e.timestamp < ?", pq.Before)

	if pq.Category != "*" {
		q.Where("e.category = ?", pq.Category)
	}
	if pq.AppID != "" {
		q.Where("e.app_id = ?", pq.AppID)
	}
	if pq.TenantID != "" {
		q.Where("e.tenant_id = ?", pq.TenantID)
	}

	q = q.OrderExpr("e.timestamp ASC")
	if limit := pq.EffectiveLimit(); limit > 0 {
		q = q.Limit(limit)
	}

	if err := q.Scan(ctx); err != nil {
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

// ListArchives returns archive records matching opts, scoped before pagination.
func (s *Store) ListArchives(ctx context.Context, opts retention.ListOpts) ([]*retention.Archive, error) {
	var models []ArchiveModel
	q := s.pg.NewSelect(&models)

	if opts.AppID != "" {
		q.Where("a.app_id = ?", opts.AppID)
	}
	if opts.TenantID != "" {
		q.Where("a.tenant_id = ?", opts.TenantID)
	}

	q = q.OrderExpr("a.created_at DESC")
	if opts.Limit > 0 {
		q = q.Limit(opts.Limit)
	}
	if opts.Offset > 0 {
		q = q.Offset(opts.Offset)
	}

	if err := q.Scan(ctx); err != nil {
		return nil, err
	}

	archives := make([]*retention.Archive, 0, len(models))
	for i := range models {
		a, convErr := toArchive(&models[i])
		if convErr != nil {
			return nil, convErr
		}
		archives = append(archives, a)
	}

	return archives, nil
}
