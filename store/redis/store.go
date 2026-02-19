// Package redis implements a Redis-backed cache for recent audit events and statistics.
// This is a partial store -- it caches recent events and provides fast stats lookups.
// It is NOT a full audit.Store and should be used alongside a primary store (e.g. postgres).
package redis

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// Store implements a Redis-backed cache for recent events and statistics.
// This is a partial store -- it caches recent events and provides fast stats lookups.
// It is NOT a full audit.Store and should be used alongside a primary store.
type Store struct {
	client    *redis.Client
	prefix    string
	ttl       time.Duration
	maxRecent int64
}

// Option configures the Redis store.
type Option func(*Store)

// WithPrefix sets the key prefix (default: "chronicle:").
func WithPrefix(prefix string) Option {
	return func(s *Store) { s.prefix = prefix }
}

// WithTTL sets the cache TTL (default: 24 hours).
func WithTTL(ttl time.Duration) Option {
	return func(s *Store) { s.ttl = ttl }
}

// WithMaxRecent sets how many recent events to keep per scope (default: 1000).
func WithMaxRecent(n int64) Option {
	return func(s *Store) { s.maxRecent = n }
}

// New creates a new Redis cache store.
func New(client *redis.Client, opts ...Option) *Store {
	s := &Store{
		client:    client,
		prefix:    "chronicle:",
		ttl:       24 * time.Hour,
		maxRecent: 1000,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// key builds a Redis key from the prefix and path segments.
func (s *Store) key(parts ...string) string {
	k := s.prefix
	for i, p := range parts {
		if i > 0 {
			k += ":"
		}
		k += p
	}
	return k
}

// Ping checks Redis connectivity.
func (s *Store) Ping(ctx context.Context) error {
	return s.client.Ping(ctx).Err()
}

// Close closes the Redis client.
func (s *Store) Close() error {
	return s.client.Close()
}
