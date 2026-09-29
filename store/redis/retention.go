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
	TenantID  string    `json:"tenant_id"`
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
		TenantID:  p.TenantID,
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
		TenantID: m.TenantID,
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
	AppID         string    `json:"app_id"`
	TenantID      string    `json:"tenant_id"`
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
		AppID:         a.AppID,
		TenantID:      a.TenantID,
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
		AppID:         m.AppID,
		TenantID:      m.TenantID,
	}, nil
}

// SavePolicy persists a retention policy, replacing any existing policy for the
// same (app, tenant, category).
//
// The uniqueness key includes the owning scope. Keying on category alone let a
// save from one app evict another app's policy for that category.
func (s *Store) SavePolicy(ctx context.Context, p *retention.Policy) error {
	m := toPolicyModel(p)

	scopeKey := policyScopeKey(m.AppID, m.TenantID, m.Category)
	existingID, err := s.rdb.Get(ctx, scopeKey).Result()
	if err == nil && existingID != "" && existingID != m.ID {
		// Replace this scope's previous policy for the category.
		s.rdb.Del(ctx, entityKey(prefixPolicy, existingID))
		s.rdb.ZRem(ctx, zPolicyAll, existingID)
	}

	key := entityKey(prefixPolicy, m.ID)
	if setErr := s.setEntity(ctx, key, m); setErr != nil {
		return fmt.Errorf("chronicle/redis: save policy: %w", setErr)
	}

	pipe := s.rdb.Pipeline()
	pipe.ZAdd(ctx, zPolicyAll, goredis.Z{Score: scoreFromTime(m.CreatedAt), Member: m.ID})
	pipe.Set(ctx, scopeKey, m.ID, 0)
	if _, err := pipe.Exec(ctx); err != nil {
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

// ListPolicies returns retention policies matching opts, scoped before
// pagination so a caller's own rows are never hidden behind another tenant's.
func (s *Store) ListPolicies(
	ctx context.Context, opts retention.ListPoliciesOpts,
) ([]*retention.Policy, error) {
	ids, err := s.rdb.ZRevRange(ctx, zPolicyAll, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("chronicle/redis: list policies: %w", err)
	}

	result := make([]*retention.Policy, 0, len(ids))
	for _, entryID := range ids {
		var m policyModel
		if getErr := s.getEntity(ctx, entityKey(prefixPolicy, entryID), &m); getErr != nil {
			if isNotFound(getErr) {
				continue
			}
			return nil, getErr
		}
		if opts.AppID != "" && m.AppID != opts.AppID {
			continue
		}
		if opts.TenantID != "" && m.TenantID != opts.TenantID {
			continue
		}
		p, convErr := fromPolicyModel(&m)
		if convErr != nil {
			return nil, convErr
		}
		result = append(result, p)
	}

	return applyPagination(result, opts.Offset, opts.Limit), nil
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
	pipe.Del(ctx, policyScopeKey(m.AppID, m.TenantID, m.Category))
	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("chronicle/redis: delete policy indexes: %w", err)
	}
	return nil
}

// EventsOlderThan returns the events the purge query selects.
//
// Security-critical: the scope filter is what keeps one tenant's policy from
// selecting, and therefore purging, every tenant's history. The scope matches
// exactly, so an empty TenantID means untenanted events rather than every
// tenant. The bound keeps a large backlog from being loaded into memory all at
// once.
func (s *Store) EventsOlderThan(
	ctx context.Context, pq retention.PurgeQuery,
) ([]*audit.Event, error) {
	maxScore := scoreFromTime(pq.Before)

	// The scope index holds exactly one (app, tenant) pair, empty values
	// included, so it is always the right index for a purge. The app and
	// category indexes would read other tenants' events.
	zKey := eventScopeKey(pq.AppID, pq.TenantID)

	ids, err := s.zRangeByScoreIDs(ctx, zKey, math.Inf(-1), maxScore)
	if err != nil {
		return nil, fmt.Errorf("chronicle/redis: events older than: %w", err)
	}

	limit := pq.EffectiveLimit()

	events := make([]*audit.Event, 0, len(ids))
	for _, eid := range ids {
		if limit > 0 && len(events) == limit {
			break
		}

		var m eventModel
		if getErr := s.getEntity(ctx, entityKey(prefixEvent, eid), &m); getErr != nil {
			if isNotFound(getErr) {
				continue
			}
			return nil, getErr
		}
		if !m.Timestamp.Before(pq.Before) {
			continue
		}
		if pq.Category != "*" && m.Category != pq.Category {
			continue
		}
		// Retention records are what keep purged sequences verifiable; they
		// are never themselves up for retention.
		if m.Category == audit.CategoryRetention {
			continue
		}
		// Checked again per event: the index key joins app and tenant with
		// ":", so two different pairs can share one key.
		if m.AppID != pq.AppID || m.TenantID != pq.TenantID {
			continue
		}
		evt, convErr := fromEventModel(&m)
		if convErr != nil {
			return nil, convErr
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
		pipe.ZRem(ctx, eventScopeKey(m.AppID, m.TenantID), m.ID)
		pipe.ZRem(ctx, zEventApp+m.AppID, m.ID)
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
		if opts.AppID != "" && m.AppID != opts.AppID {
			continue
		}
		if opts.TenantID != "" && m.TenantID != opts.TenantID {
			continue
		}
		a, convErr := fromArchiveModel(&m)
		if convErr != nil {
			return nil, convErr
		}
		result = append(result, a)
	}

	return applyPagination(result, opts.Offset, opts.Limit), nil
}
