package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/redis/go-redis/v9"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
)

// CacheEvent stores a single event in the Redis cache.
// It serialises the event as JSON, adds it to the per-scope recent events sorted set
// (scored by timestamp), trims the set to maxRecent, and tracks action statistics.
func (s *Store) CacheEvent(ctx context.Context, event *audit.Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("redis cache: marshal event: %w", err)
	}

	eventKey := s.key("events", event.ID.String())
	recentKey := s.key("recent", event.AppID, event.TenantID)
	score := float64(event.Timestamp.UnixNano())

	pipe := s.client.Pipeline()
	pipe.Set(ctx, eventKey, data, s.ttl)
	pipe.ZAdd(ctx, recentKey, redis.Z{Score: score, Member: event.ID.String()})
	pipe.ZRemRangeByRank(ctx, recentKey, 0, -s.maxRecent-1)
	pipe.Expire(ctx, recentKey, s.ttl)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redis cache: cache event pipeline: %w", err)
	}

	if err := s.TrackAction(ctx, event); err != nil {
		return fmt.Errorf("redis cache: track action: %w", err)
	}

	return nil
}

// GetCachedEvent retrieves a single cached event by its ID.
// Returns chronicle.ErrEventNotFound if the event is not in the cache.
func (s *Store) GetCachedEvent(ctx context.Context, eventID id.ID) (*audit.Event, error) {
	eventKey := s.key("events", eventID.String())

	data, err := s.client.Get(ctx, eventKey).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, chronicle.ErrEventNotFound
		}
		return nil, fmt.Errorf("redis cache: get event: %w", err)
	}

	var event audit.Event
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, fmt.Errorf("redis cache: unmarshal event: %w", err)
	}

	return &event, nil
}

// RecentEvents returns the most recent events for a given scope.
// Events are returned in reverse chronological order (most recent first).
func (s *Store) RecentEvents(ctx context.Context, appID, tenantID string, limit int64) ([]*audit.Event, error) {
	recentKey := s.key("recent", appID, tenantID)

	ids, err := s.client.ZRangeArgs(ctx, redis.ZRangeArgs{
		Key:   recentKey,
		Start: 0,
		Stop:  limit - 1,
		Rev:   true,
	}).Result()
	if err != nil {
		return nil, fmt.Errorf("redis cache: recent events zrevrange: %w", err)
	}

	if len(ids) == 0 {
		return nil, nil
	}

	// Build event keys for the returned IDs.
	eventKeys := make([]string, len(ids))
	for i, eid := range ids {
		eventKeys[i] = s.key("events", eid)
	}

	vals, err := s.client.MGet(ctx, eventKeys...).Result()
	if err != nil {
		return nil, fmt.Errorf("redis cache: recent events mget: %w", err)
	}

	events := make([]*audit.Event, 0, len(vals))
	for _, v := range vals {
		if v == nil {
			continue
		}
		str, ok := v.(string)
		if !ok {
			continue
		}
		var event audit.Event
		if err := json.Unmarshal([]byte(str), &event); err != nil {
			continue // skip malformed entries
		}
		events = append(events, &event)
	}

	return events, nil
}

// CacheBatch stores multiple events in the Redis cache using a pipeline.
func (s *Store) CacheBatch(ctx context.Context, events []*audit.Event) error {
	pipe := s.client.Pipeline()

	for _, event := range events {
		data, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("redis cache: marshal event %s: %w", event.ID.String(), err)
		}

		eventKey := s.key("events", event.ID.String())
		recentKey := s.key("recent", event.AppID, event.TenantID)
		score := float64(event.Timestamp.UnixNano())

		pipe.Set(ctx, eventKey, data, s.ttl)
		pipe.ZAdd(ctx, recentKey, redis.Z{Score: score, Member: event.ID.String()})
		pipe.ZRemRangeByRank(ctx, recentKey, 0, -s.maxRecent-1)
		pipe.Expire(ctx, recentKey, s.ttl)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redis cache: cache batch pipeline: %w", err)
	}

	// Track stats for each event after the cache pipeline succeeds.
	for _, event := range events {
		if err := s.TrackAction(ctx, event); err != nil {
			return fmt.Errorf("redis cache: track action for %s: %w", event.ID.String(), err)
		}
	}

	return nil
}
