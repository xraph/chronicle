package mongo

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
)

// SavePolicy persists a retention policy, upserting on the owning scope plus
// the category.
//
// The filter matches the full scope, not the category alone, so one app cannot
// overwrite or take ownership of another app's policy. SetUpsert is what makes
// the first save persist: UpdateOne against a filter that matches nothing
// returns MatchedCount 0 and a nil error, so an insert fallback guarded by
// `if err != nil` would never run and the write would be silently dropped.
func (s *Store) SavePolicy(ctx context.Context, p *retention.Policy) error {
	m := fromPolicy(p)

	filter := bson.M{
		"app_id":    m.AppID,
		"tenant_id": m.TenantID,
		"category":  m.Category,
	}
	update := bson.M{
		"$set": bson.M{
			"duration":   m.Duration,
			"archive":    m.Archive,
			"updated_at": m.UpdatedAt,
		},
		"$setOnInsert": bson.M{
			"_id":        m.ID,
			"app_id":     m.AppID,
			"tenant_id":  m.TenantID,
			"category":   m.Category,
			"created_at": m.CreatedAt,
		},
	}

	if _, err := s.mdb.Collection(colPolicies).UpdateOne(
		ctx, filter, update, options.UpdateOne().SetUpsert(true),
	); err != nil {
		return fmt.Errorf("failed to save policy: %w", err)
	}
	return nil
}

// GetPolicy returns a retention policy by ID.
func (s *Store) GetPolicy(ctx context.Context, policyID id.ID) (*retention.Policy, error) {
	var m RetentionPolicyModel
	err := s.mdb.NewFind(&m).Filter(bson.M{"_id": policyID.String()}).Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, chronicle.ErrPolicyNotFound
		}
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}

	p, err := toPolicy(&m)
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
	findQ := s.mdb.NewFind(&models).
		Filter(scopeFilter(opts.AppID, opts.TenantID)).
		Sort(bson.D{{Key: "created_at", Value: -1}})

	if opts.Limit > 0 {
		findQ = findQ.Limit(int64(opts.Limit))
	}
	if opts.Offset > 0 {
		findQ = findQ.Skip(int64(opts.Offset))
	}

	if err := findQ.Scan(ctx); err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
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

// scopeFilter builds a bson filter for an optional app/tenant scope. An empty
// value means "unscoped", which only trusted in-process callers may use.
func scopeFilter(appID, tenantID string) bson.M {
	filter := bson.M{}
	if appID != "" {
		filter["app_id"] = appID
	}
	if tenantID != "" {
		filter["tenant_id"] = tenantID
	}
	return filter
}

// DeletePolicy removes a retention policy.
func (s *Store) DeletePolicy(ctx context.Context, policyID id.ID) error {
	res, err := s.mdb.NewDelete((*RetentionPolicyModel)(nil)).
		Filter(bson.M{"_id": policyID.String()}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	if res.DeletedCount() == 0 {
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
	filter := scopeFilter(pq.AppID, pq.TenantID)
	filter["timestamp"] = bson.M{"$lt": pq.Before}
	if pq.Category != "*" {
		filter["category"] = pq.Category
	}

	var models []EventModel
	findQ := s.mdb.NewFind(&models).
		Filter(filter).
		Sort(bson.D{{Key: "timestamp", Value: 1}})

	if limit := pq.EffectiveLimit(); limit > 0 {
		findQ = findQ.Limit(int64(limit))
	}

	if err := findQ.Scan(ctx); err != nil {
		return nil, fmt.Errorf("failed to query old events: %w", err)
	}

	return toEventSlice(models)
}

// PurgeEvents permanently deletes events by IDs.
func (s *Store) PurgeEvents(ctx context.Context, eventIDs []id.ID) (int64, error) {
	if len(eventIDs) == 0 {
		return 0, nil
	}

	ids := make([]string, 0, len(eventIDs))
	for _, eid := range eventIDs {
		ids = append(ids, eid.String())
	}

	result, err := s.mdb.Collection(colEvents).DeleteMany(ctx, bson.M{"_id": bson.M{"$in": ids}})
	if err != nil {
		return 0, fmt.Errorf("failed to purge events: %w", err)
	}

	return result.DeletedCount, nil
}

// RecordArchive records that a batch of events was archived.
func (s *Store) RecordArchive(ctx context.Context, a *retention.Archive) error {
	m := fromArchive(a)
	_, err := s.mdb.NewInsert(m).Exec(ctx)
	return err
}

// ListArchives returns archive records with pagination.
func (s *Store) ListArchives(ctx context.Context, opts retention.ListOpts) ([]*retention.Archive, error) {
	var models []ArchiveModel
	findQ := s.mdb.NewFind(&models).
		Filter(scopeFilter(opts.AppID, opts.TenantID)).
		Sort(bson.D{{Key: "created_at", Value: -1}})

	if opts.Limit > 0 {
		findQ = findQ.Limit(int64(opts.Limit))
	}
	if opts.Offset > 0 {
		findQ = findQ.Skip(int64(opts.Offset))
	}

	if err := findQ.Scan(ctx); err != nil {
		return nil, fmt.Errorf("failed to list archives: %w", err)
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
