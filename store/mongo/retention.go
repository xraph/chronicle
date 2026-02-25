package mongo

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
)

// SavePolicy persists a retention policy (upsert by category).
func (s *Store) SavePolicy(ctx context.Context, p *retention.Policy) error {
	m := fromPolicy(p)

	// Try to find existing by category and update, or insert new.
	filter := bson.M{"category": m.Category}
	update := bson.M{"$set": bson.M{
		"_id":        m.ID,
		"category":   m.Category,
		"duration":   m.Duration,
		"archive":    m.Archive,
		"app_id":     m.AppID,
		"created_at": m.CreatedAt,
		"updated_at": m.UpdatedAt,
	}}

	_, err := s.mdb.Collection(colPolicies).UpdateOne(ctx, filter, update, nil)
	if err != nil {
		// If no match, insert.
		_, err = s.mdb.NewInsert(m).Exec(ctx)
		return err
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

// ListPolicies returns all retention policies.
func (s *Store) ListPolicies(ctx context.Context) ([]*retention.Policy, error) {
	var models []RetentionPolicyModel
	err := s.mdb.NewFind(&models).
		Filter(bson.M{}).
		Sort(bson.D{{Key: "created_at", Value: -1}}).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
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

// EventsOlderThan returns events older than a given time for a category.
func (s *Store) EventsOlderThan(ctx context.Context, category string, before time.Time) ([]*audit.Event, error) {
	var models []EventModel
	err := s.mdb.NewFind(&models).
		Filter(bson.M{
			"category":  category,
			"timestamp": bson.M{"$lt": before},
		}).
		Sort(bson.D{{Key: "timestamp", Value: 1}}).
		Scan(ctx)
	if err != nil {
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
		Filter(bson.M{}).
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
		a, err := toArchive(&models[i])
		if err != nil {
			return nil, err
		}
		archives = append(archives, a)
	}

	return archives, nil
}
