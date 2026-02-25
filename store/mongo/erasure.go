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
		Filter(bson.M{}).
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

// CountBySubject returns the number of events for a subject.
func (s *Store) CountBySubject(ctx context.Context, subjectID string) (int64, error) {
	count, err := s.mdb.Collection(colEvents).CountDocuments(ctx, bson.M{"subject_id": subjectID})
	return count, err
}

// MarkErased updates events to show [ERASED] for a given subject.
func (s *Store) MarkErased(ctx context.Context, subjectID string, erasureID id.ID) (int64, error) {
	now := time.Now().UTC()
	result, err := s.mdb.Collection(colEvents).UpdateMany(ctx,
		bson.M{"subject_id": subjectID},
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
