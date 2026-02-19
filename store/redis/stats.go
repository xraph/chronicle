package redis

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/redis/go-redis/v9"

	"github.com/xraph/chronicle/audit"
)

// Stats holds aggregated event statistics for a single scope (appID + tenantID).
type Stats struct {
	TotalEvents int64            `json:"total_events"`
	ByCategory  map[string]int64 `json:"by_category"`
	ByAction    map[string]int64 `json:"by_action"`
	BySeverity  map[string]int64 `json:"by_severity"`
	ByOutcome   map[string]int64 `json:"by_outcome"`
}

// IncrementCounter increments a named counter for the given scope by delta.
// The counter is stored as a field in a Redis hash keyed by scope.
func (s *Store) IncrementCounter(ctx context.Context, appID, tenantID, metric string, delta int64) error {
	hashKey := s.key("stats", appID, tenantID)
	if err := s.client.HIncrBy(ctx, hashKey, metric, delta).Err(); err != nil {
		return fmt.Errorf("redis stats: increment counter %q: %w", metric, err)
	}
	return nil
}

// GetCounter returns the current value of a named counter for the given scope.
// Returns 0 if the counter does not exist.
func (s *Store) GetCounter(ctx context.Context, appID, tenantID, metric string) (int64, error) {
	hashKey := s.key("stats", appID, tenantID)

	val, err := s.client.HGet(ctx, hashKey, metric).Int64()
	if err != nil {
		// redis.Nil means the field does not exist; treat as zero.
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		return 0, fmt.Errorf("redis stats: get counter %q: %w", metric, err)
	}

	return val, nil
}

// TrackAction records statistics derived from a single audit event.
// It increments the following hash fields for the event's scope:
//
//	total_events, category:{cat}, action:{act}, severity:{sev}, outcome:{out}
func (s *Store) TrackAction(ctx context.Context, event *audit.Event) error {
	hashKey := s.key("stats", event.AppID, event.TenantID)

	pipe := s.client.Pipeline()
	pipe.HIncrBy(ctx, hashKey, "total_events", 1)

	if event.Category != "" {
		pipe.HIncrBy(ctx, hashKey, "category:"+event.Category, 1)
	}
	if event.Action != "" {
		pipe.HIncrBy(ctx, hashKey, "action:"+event.Action, 1)
	}
	if event.Severity != "" {
		pipe.HIncrBy(ctx, hashKey, "severity:"+event.Severity, 1)
	}
	if event.Outcome != "" {
		pipe.HIncrBy(ctx, hashKey, "outcome:"+event.Outcome, 1)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("redis stats: track action pipeline: %w", err)
	}

	return nil
}

// GetStats returns all tracked statistics for the given scope.
// It reads the entire stats hash and partitions the fields by prefix.
func (s *Store) GetStats(ctx context.Context, appID, tenantID string) (*Stats, error) {
	hashKey := s.key("stats", appID, tenantID)

	fields, err := s.client.HGetAll(ctx, hashKey).Result()
	if err != nil {
		return nil, fmt.Errorf("redis stats: hgetall: %w", err)
	}

	stats := &Stats{
		ByCategory: make(map[string]int64),
		ByAction:   make(map[string]int64),
		BySeverity: make(map[string]int64),
		ByOutcome:  make(map[string]int64),
	}

	for field, raw := range fields {
		val, parseErr := strconv.ParseInt(raw, 10, 64)
		if parseErr != nil {
			continue // skip non-integer fields
		}

		switch {
		case field == "total_events":
			stats.TotalEvents = val
		case strings.HasPrefix(field, "category:"):
			stats.ByCategory[strings.TrimPrefix(field, "category:")] = val
		case strings.HasPrefix(field, "action:"):
			stats.ByAction[strings.TrimPrefix(field, "action:")] = val
		case strings.HasPrefix(field, "severity:"):
			stats.BySeverity[strings.TrimPrefix(field, "severity:")] = val
		case strings.HasPrefix(field, "outcome:"):
			stats.ByOutcome[strings.TrimPrefix(field, "outcome:")] = val
		}
	}

	return stats, nil
}
