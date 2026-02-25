package redis

import (
	"context"
	"fmt"
	"math"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/retention"
)

// policyModel is the JSON representation stored in Redis.
type policyModel struct {
	ID        string    `json:"id"`
	Category  string    `json:"category"`
	Duration  int64     `json:"duration"` // nanoseconds
	Archive   bool      `json:"archive"`
	AppID     string    `json:"app_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func toPolicyModel(p *retention.Policy) *policyModel {
	return &policyModel{
		ID:        p.ID.String(),
		Category:  p.Category,
		Duration:  int64(p.Duration),
		Archive:   p.Archive,
		AppID:     p.AppID,
		CreatedAt: p.CreatedAt,
		UpdatedAt: p.UpdatedAt,
	}
}

func fromPolicyModel(m *policyModel) (*retention.Policy, error) {
	policyID, err := id.ParsePolicyID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse policy ID %q: %w", m.ID, err)
	}
	return &retention.Policy{
		Entity: chronicle.Entity{
			CreatedAt: m.CreatedAt,
			UpdatedAt: m.UpdatedAt,
		},
		ID:       policyID,
		Category: m.Category,
		Duration: time.Duration(m.Duration),
		Archive:  m.Archive,
		AppID:    m.AppID,
	}, nil
}

// archiveModel is the JSON representation stored in Redis.
type archiveModel struct {
	ID            string    `json:"id"`
	PolicyID      string    `json:"policy_id"`
	Category      string    `json:"category"`
	EventCount    int64     `json:"event_count"`
	FromTimestamp time.Time `json:"from_timestamp"`
	ToTimestamp   time.Time `json:"to_timestamp"`
	SinkName      string    `json:"sink_name"`
	SinkRef       string    `json:"sink_ref"`
	CreatedAt     time.Time `json:"created_at"`
}

func toArchiveModel(a *retention.Archive) *archiveModel {
	return &archiveModel{
		ID:            a.ID.String(),
		PolicyID:      a.PolicyID.String(),
		Category:      a.Category,
		EventCount:    a.EventCount,
		FromTimestamp: a.FromTimestamp,
		ToTimestamp:   a.ToTimestamp,
		SinkName:      a.SinkName,
		SinkRef:       a.SinkRef,
		CreatedAt:     a.CreatedAt,
	}
}

func fromArchiveModel(m *archiveModel) (*retention.Archive, error) {
	archiveID, err := id.ParseArchiveID(m.ID)
	if err != nil {
		return nil, fmt.Errorf("parse archive ID %q: %w", m.ID, err)
	}
	policyID, err := id.ParsePolicyID(m.PolicyID)
	if err != nil {
		return nil, fmt.Errorf("parse policy ID %q: %w", m.PolicyID, err)
	}
	return &retention.Archive{
		Entity: chronicle.Entity{
			CreatedAt: m.CreatedAt,
		},
		ID:            archiveID,
		PolicyID:      policyID,
		Category:      m.Category,
		EventCount:    m.EventCount,
		FromTimestamp: m.FromTimestamp,
		ToTimestamp:   m.ToTimestamp,
		SinkName:      m.SinkName,
		SinkRef:       m.SinkRef,
	}, nil
}

// SavePolicy persists a retention policy (upsert by category).
func (s *Store) SavePolicy(ctx context.Context, p *retention.Policy) error {
	m := toPolicyModel(p)

	// Check if a policy for this category already exists.
	catKey := uniquePolicyCategory + m.Category
	existingID, err := s.rdb.Get(ctx, catKey).Result()
	if err == nil && existingID != "" && existingID != m.ID {
		// Remove the old policy.
		s.rdb.Del(ctx, entityKey(prefixPolicy, existingID))
		s.rdb.ZRem(ctx, zPolicyAll, existingID)
	}

	key := entityKey(prefixPolicy, m.ID)
	if setErr := s.setEntity(ctx, key, m); setErr != nil {
		return fmt.Errorf("chronicle/redis: save policy: %w", setErr)
	}

	pipe := s.rdb.Pipeline()
	pipe.ZAdd(ctx, zPolicyAll, goredis.Z{Score: scoreFromTime(m.CreatedAt), Member: m.ID})
	pipe.Set(ctx, catKey, m.ID, 0)
	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("chronicle/redis: save policy indexes: %w", err)
	}
	return nil
}

// GetPolicy returns a retention policy by ID.
func (s *Store) GetPolicy(ctx context.Context, policyID id.ID) (*retention.Policy, error) {
	var m policyModel
	if err := s.getEntity(ctx, entityKey(prefixPolicy, policyID.String()), &m); err != nil {
		if isNotFound(err) {
			return nil, chronicle.ErrPolicyNotFound
		}
		return nil, fmt.Errorf("chronicle/redis: get policy: %w", err)
	}
	return fromPolicyModel(&m)
}

// ListPolicies returns all retention policies.
func (s *Store) ListPolicies(ctx context.Context) ([]*retention.Policy, error) {
	ids, err := s.rdb.ZRevRange(ctx, zPolicyAll, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("chronicle/redis: list policies: %w", err)
	}

	result := make([]*retention.Policy, 0, len(ids))
	for _, entryID := range ids {
		var m policyModel
		if err := s.getEntity(ctx, entityKey(prefixPolicy, entryID), &m); err != nil {
			if isNotFound(err) {
				continue
			}
			return nil, err
		}
		p, err := fromPolicyModel(&m)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}

	return result, nil
}

// DeletePolicy removes a retention policy.
func (s *Store) DeletePolicy(ctx context.Context, policyID id.ID) error {
	key := entityKey(prefixPolicy, policyID.String())

	var m policyModel
	if err := s.getEntity(ctx, key, &m); err != nil {
		if isNotFound(err) {
			return fmt.Errorf("%w: policy %s", chronicle.ErrPolicyNotFound, policyID)
		}
		return fmt.Errorf("chronicle/redis: delete policy get: %w", err)
	}

	if err := s.kv.Delete(ctx, key); err != nil {
		return fmt.Errorf("chronicle/redis: delete policy: %w", err)
	}

	pipe := s.rdb.Pipeline()
	pipe.ZRem(ctx, zPolicyAll, m.ID)
	pipe.Del(ctx, uniquePolicyCategory+m.Category)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("chronicle/redis: delete policy indexes: %w", err)
	}
	return nil
}

// EventsOlderThan returns events older than a given time for a category.
func (s *Store) EventsOlderThan(ctx context.Context, category string, before time.Time) ([]*audit.Event, error) {
	maxScore := scoreFromTime(before)
	ids, err := s.zRangeByScoreIDs(ctx, zEventCategory+category, math.Inf(-1), maxScore)
	if err != nil {
		return nil, fmt.Errorf("chronicle/redis: events older than: %w", err)
	}

	events := make([]*audit.Event, 0, len(ids))
	for _, eid := range ids {
		var m eventModel
		if err := s.getEntity(ctx, entityKey(prefixEvent, eid), &m); err != nil {
			if isNotFound(err) {
				continue
			}
			return nil, err
		}
		// Double-check category and time filter.
		if m.Category != category || !m.Timestamp.Before(before) {
			continue
		}
		evt, err := fromEventModel(&m)
		if err != nil {
			return nil, err
		}
		events = append(events, evt)
	}

	return events, nil
}

// PurgeEvents permanently deletes events by IDs.
func (s *Store) PurgeEvents(ctx context.Context, eventIDs []id.ID) (int64, error) {
	if len(eventIDs) == 0 {
		return 0, nil
	}

	var count int64
	for _, eid := range eventIDs {
		key := entityKey(prefixEvent, eid.String())

		// Get event data to clean up indexes.
		var m eventModel
		if err := s.getEntity(ctx, key, &m); err != nil {
			if isNotFound(err) {
				continue
			}
			return count, err
		}

		// Delete the entity.
		if err := s.kv.Delete(ctx, key); err != nil {
			return count, err
		}

		// Clean up indexes.
		pipe := s.rdb.Pipeline()
		pipe.ZRem(ctx, zEventAll, m.ID)
		pipe.ZRem(ctx, zEventStream+m.StreamID, m.ID)
		pipe.ZRem(ctx, zEventScope+m.AppID+":"+m.TenantID, m.ID)
		if m.Category != "" {
			pipe.ZRem(ctx, zEventCategory+m.Category, m.ID)
		}
		if m.UserID != "" {
			pipe.ZRem(ctx, zEventUser+m.UserID, m.ID)
		}
		if m.SubjectID != "" {
			pipe.ZRem(ctx, zEventSubject+m.SubjectID, m.ID)
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return count, fmt.Errorf("chronicle/redis: purge event indexes: %w", err)
		}

		count++
	}

	return count, nil
}

// RecordArchive records that a batch of events was archived.
func (s *Store) RecordArchive(ctx context.Context, a *retention.Archive) error {
	m := toArchiveModel(a)
	key := entityKey(prefixArchive, m.ID)

	if err := s.setEntity(ctx, key, m); err != nil {
		return fmt.Errorf("chronicle/redis: record archive: %w", err)
	}

	s.rdb.ZAdd(ctx, zArchiveAll, goredis.Z{Score: scoreFromTime(m.CreatedAt), Member: m.ID})
	return nil
}

// ListArchives returns archive records with pagination.
func (s *Store) ListArchives(ctx context.Context, opts retention.ListOpts) ([]*retention.Archive, error) {
	ids, err := s.rdb.ZRevRange(ctx, zArchiveAll, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("chronicle/redis: list archives: %w", err)
	}

	result := make([]*retention.Archive, 0, len(ids))
	for _, entryID := range ids {
		var m archiveModel
		if err := s.getEntity(ctx, entityKey(prefixArchive, entryID), &m); err != nil {
			if isNotFound(err) {
				continue
			}
			return nil, err
		}
		a, err := fromArchiveModel(&m)
		if err != nil {
			return nil, err
		}
		result = append(result, a)
	}

	return applyPagination(result, opts.Offset, opts.Limit), nil
}
