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
		if opts.AppID != "" && m.AppID != opts.AppID {
			continue
		}
		if opts.TenantID != "" && m.TenantID != opts.TenantID {
			continue
		}
		e, convErr := fromErasureModel(&m)
		if convErr != nil {
			return nil, convErr
		}
		result = append(result, e)
	}

	return applyPagination(result, opts.Offset, opts.Limit), nil
}

// CountErasures returns the number of erasure records in the given scope.
//
// Unscoped this is a single ZCARD. Scoped, the erasure index is not partitioned
// by app/tenant, so each record is read to confirm ownership.
func (s *Store) CountErasures(ctx context.Context, sc erasure.Scope) (int64, error) {
	if sc.IsZero() {
		return s.rdb.ZCard(ctx, zErasureAll).Result()
	}

	ids, err := s.rdb.ZRange(ctx, zErasureAll, 0, -1).Result()
	if err != nil {
		return 0, fmt.Errorf("chronicle/redis: count erasures: %w", err)
	}

	var count int64
	for _, entryID := range ids {
		var m erasureModel
		if getErr := s.getEntity(ctx, entityKey(prefixErasure, entryID), &m); getErr != nil {
			if isNotFound(getErr) {
				continue
			}
			return 0, getErr
		}
		if !scopeMatches(sc, m.AppID, m.TenantID) {
			continue
		}
		count++
	}
	return count, nil
}

// CountBySubject returns the number of events for a subject within the query's
// scope.
//
// Security-critical: without the scope filter this reveals how many events other
// tenants hold on the subject.
//
// The per-subject index is not partitioned by scope, so when a scope is given
// each event is read to confirm ownership. ZCard is only correct unscoped.
func (s *Store) CountBySubject(ctx context.Context, sq erasure.SubjectQuery) (int64, error) {
	if sq.Scope.IsZero() {
		return s.rdb.ZCard(ctx, zEventSubject+sq.SubjectID).Result()
	}

	ids, err := s.rdb.ZRange(ctx, zEventSubject+sq.SubjectID, 0, -1).Result()
	if err != nil {
		return 0, fmt.Errorf("chronicle/redis: count by subject: %w", err)
	}

	var count int64
	for _, eid := range ids {
		var m eventModel
		if getErr := s.getEntity(ctx, entityKey(prefixEvent, eid), &m); getErr != nil {
			if isNotFound(getErr) {
				continue
			}
			return 0, getErr
		}
		if !scopeMatches(sq.Scope, m.AppID, m.TenantID) {
			continue
		}
		count++
	}
	return count, nil
}

// scopeMatches reports whether an event belongs to the given scope. An empty
// field in the scope means "any".
func scopeMatches(s erasure.Scope, appID, tenantID string) bool {
	if s.AppID != "" && appID != s.AppID {
		return false
	}
	if s.TenantID != "" && tenantID != s.TenantID {
		return false
	}
	return true
}

// MarkErased flags a subject's events as erased within the query's scope.
//
// Security-critical: without the scope filter any caller could flag every
// tenant's events for a guessed subject ID.
func (s *Store) MarkErased(
	ctx context.Context, sq erasure.SubjectQuery, erasureID id.ID,
) (int64, error) {
	ids, err := s.rdb.ZRange(ctx, zEventSubject+sq.SubjectID, 0, -1).Result()
	if err != nil {
		return 0, fmt.Errorf("chronicle/redis: mark erased: %w", err)
	}

	nowTime := now()
	var count int64
	for _, eid := range ids {
		key := entityKey(prefixEvent, eid)
		var m eventModel
		if getErr := s.getEntity(ctx, key, &m); getErr != nil {
			if isNotFound(getErr) {
				continue
			}
			return count, getErr
		}
		if !scopeMatches(sq.Scope, m.AppID, m.TenantID) {
			continue
		}
		m.Erased = true
		m.ErasedAt = &nowTime
		m.ErasureID = erasureID.String()
		if setErr := s.setEntity(ctx, key, &m); setErr != nil {
			return count, setErr
		}
		count++
	}

	return count, nil
}
