package mongo

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/id"
)

// RecordErasure persists an erasure event.
func (s *Store) RecordErasure(ctx context.Context, e *erasure.Erasure) error {
	m := fromErasure(e)
	_, err := s.mdb.NewInsert(m).Exec(ctx)
	return err
}

// GetErasure returns an erasure record by ID.
func (s *Store) GetErasure(ctx context.Context, erasureID id.ID) (*erasure.Erasure, error) {
	var m ErasureModel
	err := s.mdb.NewFind(&m).Filter(bson.M{"_id": erasureID.String()}).Scan(ctx)
	if err != nil {
		if isNoDocuments(err) {
			return nil, chronicle.ErrErasureNotFound
		}
		return nil, fmt.Errorf("failed to get erasure: %w", err)
	}

	e, err := toErasure(&m)
	if err != nil {
		return nil, fmt.Errorf("failed to convert erasure model: %w", err)
	}

	return e, nil
}

// ListErasures returns erasure records with pagination.
func (s *Store) ListErasures(ctx context.Context, opts erasure.ListOpts) ([]*erasure.Erasure, error) {
	var models []ErasureModel
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
		return nil, fmt.Errorf("failed to list erasures: %w", err)
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

// CountErasures returns the number of erasure records in the given scope.
func (s *Store) CountErasures(ctx context.Context, sc erasure.Scope) (int64, error) {
	return s.mdb.Collection(colErasures).CountDocuments(ctx, scopeFilter(sc.AppID, sc.TenantID))
}

// CountBySubject returns the number of events for a subject within the query's
// scope.
//
// Security-critical: without the scope filter this reveals how many events other
// tenants hold on the subject.
func (s *Store) CountBySubject(ctx context.Context, sq erasure.SubjectQuery) (int64, error) {
	filter := scopeFilter(sq.AppID, sq.TenantID)
	filter["subject_id"] = sq.SubjectID
	return s.mdb.Collection(colEvents).CountDocuments(ctx, filter)
}

// MarkErased flags a subject's events as erased within the query's scope.
//
// Security-critical: without the scope filter any caller could flag every
// tenant's events for a guessed subject ID.
func (s *Store) MarkErased(
	ctx context.Context, sq erasure.SubjectQuery, erasureID id.ID,
) (int64, error) {
	filter := scopeFilter(sq.AppID, sq.TenantID)
	filter["subject_id"] = sq.SubjectID

	now := time.Now().UTC()
	result, err := s.mdb.Collection(colEvents).UpdateMany(ctx,
		filter,
		bson.M{"$set": bson.M{
			"erased":     true,
			"erased_at":  now,
			"erasure_id": erasureID.String(),
		}},
	)
	if err != nil {
		return 0, fmt.Errorf("failed to mark events erased: %w", err)
	}

	return result.ModifiedCount, nil
}
