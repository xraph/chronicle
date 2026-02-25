package redis

import (
	"context"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/erasure"
	"github.com/xraph/chronicle/id"
)

// erasureModel is the JSON representation stored in Redis.
type erasureModel struct {
	ID             string    `json:"id"`
	SubjectID      string    `json:"subject_id"`
	Reason         string    `json:"reason"`
	RequestedBy    string    `json:"requested_by"`
	EventsAffected int64     `json:"events_affected"`
	KeyDestroyed   bool      `json:"key_destroyed"`
	AppID          string    `json:"app_id"`
	TenantID       string    `json:"tenant_id"`
	CreatedAt      time.Time `json:"created_at"`
}

func toErasureModel(e *erasure.Erasure) *erasureModel {
	return &erasureModel{
		ID:             e.ID.String(),
		SubjectID:      e.SubjectID,
		Reason:         e.Reason,
		RequestedBy:    e.RequestedBy,
		EventsAffected: e.EventsAffected,
		KeyDestroyed:   e.KeyDestroyed,
		AppID:          e.AppID,
		TenantID:       e.TenantID,
		CreatedAt:      e.CreatedAt,
	}
}

func fromErasureModel(m *erasureModel) (*erasure.Erasure, error) {
	erasureID, err := id.ParseErasureID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse erasure ID %q: %w", m.ID, err)
	}
	return &erasure.Erasure{
		Entity: chronicle.Entity{
			CreatedAt: m.CreatedAt,
		},
		ID:             erasureID,
		SubjectID:      m.SubjectID,
		Reason:         m.Reason,
		RequestedBy:    m.RequestedBy,
		EventsAffected: m.EventsAffected,
		KeyDestroyed:   m.KeyDestroyed,
		AppID:          m.AppID,
		TenantID:       m.TenantID,
	}, nil
}

// RecordErasure persists an erasure event.
func (s *Store) RecordErasure(ctx context.Context, e *erasure.Erasure) error {
	m := toErasureModel(e)
	key := entityKey(prefixErasure, m.ID)

	if err := s.setEntity(ctx, key, m); err != nil {
		return fmt.Errorf("chronicle/redis: record erasure: %w", err)
	}

	s.rdb.ZAdd(ctx, zErasureAll, goredis.Z{Score: scoreFromTime(m.CreatedAt), Member: m.ID})
	return nil
}

// GetErasure returns an erasure record by ID.
func (s *Store) GetErasure(ctx context.Context, erasureID id.ID) (*erasure.Erasure, error) {
	var m erasureModel
	if err := s.getEntity(ctx, entityKey(prefixErasure, erasureID.String()), &m); err != nil {
		if isNotFound(err) {
			return nil, chronicle.ErrErasureNotFound
		}
		return nil, fmt.Errorf("chronicle/redis: get erasure: %w", err)
	}
	return fromErasureModel(&m)
}

// ListErasures returns erasure records with pagination.
func (s *Store) ListErasures(ctx context.Context, opts erasure.ListOpts) ([]*erasure.Erasure, error) {
	ids, err := s.rdb.ZRevRange(ctx, zErasureAll, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("chronicle/redis: list erasures: %w", err)
	}

	result := make([]*erasure.Erasure, 0, len(ids))
	for _, entryID := range ids {
		var m erasureModel
		if err := s.getEntity(ctx, entityKey(prefixErasure, entryID), &m); err != nil {
			if isNotFound(err) {
				continue
			}
			return nil, err
		}
		e, err := fromErasureModel(&m)
		if err != nil {
			return nil, err
		}
		result = append(result, e)
	}

	return applyPagination(result, opts.Offset, opts.Limit), nil
}

// CountBySubject returns the number of events for a subject.
func (s *Store) CountBySubject(ctx context.Context, subjectID string) (int64, error) {
	count, err := s.rdb.ZCard(ctx, zEventSubject+subjectID).Result()
	return count, err
}

// MarkErased updates events to show [ERASED] for a given subject.
func (s *Store) MarkErased(ctx context.Context, subjectID string, erasureID id.ID) (int64, error) {
	ids, err := s.rdb.ZRange(ctx, zEventSubject+subjectID, 0, -1).Result()
	if err != nil {
		return 0, fmt.Errorf("chronicle/redis: mark erased: %w", err)
	}

	nowTime := now()
	var count int64
	for _, eid := range ids {
		key := entityKey(prefixEvent, eid)
		var m eventModel
		if err := s.getEntity(ctx, key, &m); err != nil {
			if isNotFound(err) {
				continue
			}
			return count, err
		}
		m.Erased = true
		m.ErasedAt = &nowTime
		m.ErasureID = erasureID.String()
		if err := s.setEntity(ctx, key, &m); err != nil {
			return count, err
		}
		count++
	}

	return count, nil
}
